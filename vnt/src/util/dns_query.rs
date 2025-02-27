use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::time::Duration;
use std::{io, thread};

use crate::channel::socket::LocalInterface;
use anyhow::Context;
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData, ResponseCode};

thread_local! {
    static HISTORY: RefCell<HashMap<SocketAddr,usize>> = RefCell::new(HashMap::new());
}

/// 保留一个地址使用记录，使用过的地址后续不再选中，直到地址全使用过
pub fn address_choose(addrs: Vec<SocketAddr>) -> anyhow::Result<SocketAddr> {
    HISTORY.with(|history| {
        let mut available = Vec::new();
        for x in &addrs {
            let num = history.borrow().get(x).map_or(0, |v| *v);
            if num < 3 {
                available.push(*x);
            }
        }
        if available.is_empty() {
            available = addrs;
            history.borrow_mut().clear();
        }
        let addr = address_choose0(available)?;
        history
            .borrow_mut()
            .entry(addr)
            .and_modify(|v| {
                *v += 1;
            })
            .or_insert(1);
        Ok(addr)
    })
}

/// 后续实现选择延迟最低的可用地址，需要服务端配合
/// 现在是选择第一个地址，优先ipv6
fn address_choose0(addrs: Vec<SocketAddr>) -> anyhow::Result<SocketAddr> {
    let v4: Vec<SocketAddr> = addrs.iter().filter(|v| v.is_ipv4()).copied().collect();
    let v6: Vec<SocketAddr> = addrs.iter().filter(|v| v.is_ipv6()).copied().collect();
    let check_addr = |addrs: &Vec<SocketAddr>| -> anyhow::Result<SocketAddr> {
        let mut err = Vec::new();
        if !addrs.is_empty() {
            let udp = if addrs[0].is_ipv6() {
                UdpSocket::bind("[::]:0")?
            } else {
                UdpSocket::bind("0.0.0.0:0")?
            };
            for addr in addrs {
                if let Err(e) = udp.connect(addr) {
                    err.push((*addr, e));
                } else {
                    return Ok(*addr);
                }
            }
        }
        Err(anyhow::anyhow!("Unable to connect to address {:?}", err))
    };
    if v6.is_empty() {
        return check_addr(&v4);
    }
    if v4.is_empty() {
        return check_addr(&v6);
    }
    match check_addr(&v6) {
        Ok(addr) => Ok(addr),
        Err(e1) => match check_addr(&v4) {
            Ok(addr) => Ok(addr),
            Err(e2) => Err(anyhow::anyhow!("{} , {}", e1, e2)),
        },
    }
}

pub fn dns_query_all(
    domain: &str,
    mut name_servers: Vec<String>,
    default_interface: &LocalInterface,
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut current_domain = domain.to_string(); // 引入可变变量存储当前域名
    match SocketAddr::from_str(domain) {
        Ok(addr) => Ok(vec![addr]),
        Err(_) => {
            // 检查重定向地址
            if let Some(redirected_url) = check_for_redirect(&current_domain)? {

                // 去掉 URL 开头的协议部分
                let stripped_domain = remove_http_prefix(&redirected_url);
                println!("Location：{}", stripped_domain);

                // 检查是否为 IP 和端口组合
                if let Ok(socket_addr) = SocketAddr::from_str(&stripped_domain) {
                    return Ok(vec![socket_addr]); // 如果是 IP 和端口格式，直接返回结果
                } else {
                    // 如果不是 IP 和端口格式，则更新为重定向地址
                    current_domain = stripped_domain;
                }
            }

            let txt_domain = current_domain
                .to_lowercase()
                .strip_prefix("txt:")
                .map(|v| v.to_string());
            if name_servers.is_empty() {
                if txt_domain.is_some() {
                    name_servers.push("223.5.5.5:53".into());
                    name_servers.push("114.114.114.114:53".into());
                } else {
                    return Ok(current_domain
                        .to_socket_addrs()
                        .with_context(|| format!("DNS query failed {:?}", current_domain))?
                        .collect());
                }
            }

            let mut err: Option<anyhow::Error> = None;
            for name_server in name_servers {
                if let Some(domain) = txt_domain.as_ref() {
                    match txt_dns(domain, name_server, default_interface) {
                        Ok(addr) => {
                            if !addr.is_empty() {
                                return Ok(addr);
                            }
                        }
                        Err(e) => {
                            if let Some(err) = &mut err {
                                *err = anyhow::anyhow!("{} {}", err, e);
                            } else {
                                err.replace(anyhow::anyhow!("{}", e));
                            }
                        }
                    }
                    continue;
                }
                let end_index = current_domain
                    .rfind(':')
                    .with_context(|| format!("{:?} not port", current_domain))?;
                let host = &domain[..end_index];
                let port = u16::from_str(&domain[end_index + 1..])
                    .with_context(|| format!("{:?} not port", current_domain))?;
                let th1 = {
                    let host = host.to_string();
                    let name_server = name_server.clone();
                    let default_interface = default_interface.clone();
                    thread::spawn(move || a_dns(host, name_server, &default_interface))
                };
                let th2 = {
                    let host = host.to_string();
                    let name_server = name_server.clone();
                    let default_interface = default_interface.clone();
                    thread::spawn(move || aaaa_dns(host, name_server, &default_interface))
                };
                let mut addr = Vec::new();
                match th1.join().unwrap() {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        err.replace(anyhow::anyhow!("{}", e));
                    }
                }
                match th2.join().unwrap() {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        if addr.is_empty() {
                            if let Some(err) = &mut err {
                                *err = anyhow::anyhow!("{},{}", err, e);
                            } else {
                                err.replace(anyhow::anyhow!("{}", e));
                            }
                            continue;
                        }
                    }
                }
                if addr.is_empty() {
                    continue;
                }
                return Ok(addr);
            }
            if let Some(e) = err {
                Err(e)
            } else {
                Err(anyhow::anyhow!("DNS query failed {:?}", current_domain))
            }
        }
    }
}

fn check_for_redirect(domain: &String) -> anyhow::Result<Option<String>> {
    use reqwest::{blocking::Client};

    let client = Client::builder()
        .timeout(Duration::from_secs(3)) // 设置超时时间为 3 秒
        .redirect(reqwest::redirect::Policy::none()) // 禁止自动重定向，手动处理
        .build()?;

    // 确保域名有 http:// 或 https:// 前缀
    let mut url = if domain.starts_with("http://") || domain.starts_with("https://") {
        domain.clone()
    } else {
        format!("http://{}", domain)
    };

    let mut count = 0; // 重定向次数计数器
    let mut is_redirect = false; // 标记是否经历过重定向
    loop {
        count += 1;
        if count > 3 {
            // 如果重定向次数超过 3 次，则返回错误
            return Err(anyhow::anyhow!("发生多次重定向，链接终止")).into();
        }

        // 模拟发起请求，仅提取重定向地址
        let response_result = client.get(&url)
            .header("User-Agent", "Mozilla/5.0")
            .send();

        match response_result {
            Ok(response) => {
                // 检查是否为重定向状态码
                if response.status().is_redirection() {
                    is_redirect = true; // 标记发生了重定向
                    // 提取重定向地址
                    if let Some(location) = response.headers().get("Location") {
                        if let Ok(location_str) = location.to_str() {
                            // 去掉结尾的斜杠（如果有）
                            let trimmed_location = location_str.trim_end_matches('/').to_string();
                            // 如果是新的重定向地址，更新 url，继续检查
                            url = trimmed_location.clone();
                            continue; // 继续下一次重定向请求
                        }
                    }
                } else {
                    // 如果不是重定向状态码
                    if is_redirect {
                        // 如果之前发生过重定向，则返回最后获取到的重定向地址
                        return Ok(Some(url));
                    } else {
                        // 如果没有经历过重定向，则返回 None
                        return Ok(None);
                    }
                }
            }
            Err(_) => {
                // 发生任何错误时直接返回 Ok(None)，不抛出异常
                if is_redirect {
                    // 如果之前发生过重定向，则返回最后获取到的重定向地址
                      return Ok(Some(url));
                 } else {
                    // 如果没有经历过重定向，则返回 None
                    return Ok(None);
                }
            }
        }
    }
}

/// 去掉 http:// 或 https:// 前缀
fn remove_http_prefix(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .to_string()
}

fn query<'a>(
    udp: &UdpSocket,
    domain: &str,
    name_server: SocketAddr,
    record_type: QueryType,
    buf: &'a mut [u8],
) -> anyhow::Result<Packet<'a>> {
    let mut builder = Builder::new_query(1, true);
    builder.add_question(domain, false, record_type, QueryClass::IN);
    let packet = builder.build().unwrap();

    udp.connect(name_server)
        .with_context(|| format!("DNS {:?} error ", name_server))?;
    let mut count = 0;
    let len = loop {
        udp.send(&packet)?;

        match udp.recv(buf) {
            Ok(len) => {
                break len;
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    count += 1;
                    if count < 3 {
                        continue;
                    }
                }
                Err(e).with_context(|| format!("DNS {:?} recv error ", name_server))?
            }
        };
    };

    let pkt = Packet::parse(&buf[..len])
        .with_context(|| format!("domain {:?} DNS {:?} data error ", domain, name_server))?;
    if pkt.header.response_code != ResponseCode::NoError {
        return Err(anyhow::anyhow!(
            "response_code {} DNS {:?} domain {:?}",
            pkt.header.response_code,
            name_server,
            domain
        ));
    }
    if pkt.answers.is_empty() {
        return Err(anyhow::anyhow!(
            "No records received DNS {:?} domain {:?}",
            name_server,
            domain
        ));
    }

    Ok(pkt)
}

pub fn txt_dns(
    domain: &str,
    name_server: String,
    default_interface: &LocalInterface,
) -> anyhow::Result<Vec<SocketAddr>> {
    let name_server: SocketAddr = name_server.parse()?;
    let udp = bind_udp(name_server, default_interface)?;
    let mut buf = [0; 65536];
    let message = query(&udp, domain, name_server, QueryType::TXT, &mut buf)?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::TXT(txt) = record.data {
            for x in txt.iter() {
                let txt = std::str::from_utf8(x).context("record type txt is not string")?;
                let addr =
                    SocketAddr::from_str(txt).context("record type txt is not SocketAddr")?;
                rs.push(addr);
            }
        }
    }
    Ok(rs)
}

fn bind_udp(
    name_server: SocketAddr,
    default_interface: &LocalInterface,
) -> anyhow::Result<UdpSocket> {
    let addr: SocketAddr = if name_server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = crate::channel::socket::bind_udp(addr, default_interface)?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_millis(800)))?;
    Ok(socket.into())
}

pub fn a_dns(
    domain: String,
    name_server: String,
    default_interface: &LocalInterface,
) -> anyhow::Result<Vec<Ipv4Addr>> {
    let name_server: SocketAddr = name_server.parse()?;
    let udp = bind_udp(name_server, default_interface)?;
    let mut buf = [0; 65536];
    let message = query(&udp, &domain, name_server, QueryType::A, &mut buf)?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::A(a) = record.data {
            rs.push(a.0);
        }
    }
    Ok(rs)
}

pub fn aaaa_dns(
    domain: String,
    name_server: String,
    default_interface: &LocalInterface,
) -> anyhow::Result<Vec<Ipv6Addr>> {
    let name_server: SocketAddr = name_server.parse()?;
    let udp = bind_udp(name_server, default_interface)?;
    let mut buf = [0; 65536];
    let message = query(&udp, &domain, name_server, QueryType::AAAA, &mut buf)?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::AAAA(a) = record.data {
            rs.push(a.0);
        }
    }
    Ok(rs)
}
