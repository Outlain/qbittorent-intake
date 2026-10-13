//! Libarchive may tolerate truncated end records or trailing bytes. This bounded
//! framing pass closes those gaps before extraction and records RAR checksums.
use super::*;
use std::os::unix::fs::FileExt;
#[derive(Debug)]
pub(super) struct Member {
    pub size: u64,
    pub crc: Option<u32>,
    pub packed: u64,
}
fn read(file: &File, position: u64, length: usize) -> Result<Vec<u8>, ScanError> {
    let mut bytes = vec![0; length];
    let mut total = 0;
    while total < length {
        let n = file.read_at(&mut bytes[total..], position + total as u64)?;
        if n == 0 {
            break;
        }
        total += n;
    }
    bytes.truncate(total);
    Ok(bytes)
}
fn u16le(bytes: &[u8], offset: usize) -> Result<u16, ScanError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| blocked("truncated archive header"))?
            .try_into()
            .unwrap(),
    ))
}
fn u32le(bytes: &[u8], offset: usize) -> Result<u32, ScanError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or_else(|| blocked("truncated archive header"))?
            .try_into()
            .unwrap(),
    ))
}
fn vint(bytes: &[u8], offset: &mut usize) -> Result<u64, ScanError> {
    let mut value = 0;
    for shift in (0..63).step_by(7) {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| blocked("truncated RAR variable integer"))?;
        *offset += 1;
        value |= ((byte & 127) as u64) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(blocked("invalid RAR variable integer"))
}
pub(super) fn validate(
    file: &File,
    format: Format,
    max_headers: u64,
) -> Result<Option<Vec<Member>>, ScanError> {
    let size = file.metadata()?.len();
    if format == Format::Zip {
        let tail = read(file, size.saturating_sub(65557), size.min(65557) as usize)?;
        let offset = tail
            .windows(4)
            .rposition(|b| b == b"PK\x05\x06")
            .ok_or_else(|| blocked("ZIP central directory is missing"))?;
        if tail.len() - offset < 22 {
            return Err(blocked("truncated ZIP end record"));
        }
        if u16le(&tail, offset + 4)? != 0
            || u16le(&tail, offset + 6)? != 0
            || u16le(&tail, offset + 8)? != u16le(&tail, offset + 10)?
            || read(file, 0, 4)? == b"PK\x07\x08"
        {
            return Err(blocked("multipart ZIP archives are not supported"));
        }
        if offset + 22 + u16le(&tail, offset + 20)? as usize != tail.len() {
            return Err(blocked("ZIP end record has truncation or trailing bytes"));
        }
        let end = size - tail.len() as u64 + offset as u64;
        let locator = read(file, end.saturating_sub(20), 20)?;
        if locator.starts_with(b"PK\x06\x07")
            && (u32le(&locator, 4)? != 0 || u32le(&locator, 16)? != 1)
        {
            return Err(blocked("multipart ZIP64 archives are not supported"));
        }
        return Ok(None);
    }
    let mut position = if format == Format::Rar { 7 } else { 8 };
    let mut members = vec![];
    for number in 0..max_headers {
        let prefix = read(file, position, 16)?;
        if prefix.len() < 7 {
            return Err(blocked("RAR end header is missing or truncated"));
        }
        let mut data_size = 0;
        let header_size;
        let end;
        if format == Format::Rar {
            let crc = u16le(&prefix, 0)?;
            let kind = prefix[2];
            let flags = u16le(&prefix, 3)?;
            header_size = u16le(&prefix, 5)? as usize;
            if header_size < 7 {
                return Err(blocked("invalid RAR header size"));
            }
            let header = read(file, position, header_size)?;
            if header.len() != header_size || crc32fast::hash(&header[2..]) as u16 != crc {
                return Err(blocked("RAR header checksum/truncation error"));
            }
            if number == 0 && (kind != 0x73 || header_size < 13) {
                return Err(blocked("invalid RAR main header"));
            }
            if (kind == 0x73 && flags & 0x80 != 0) || (kind == 0x74 && flags & 4 != 0) {
                return Err(blocked("encrypted RAR cannot be inspected"));
            }
            if (kind == 0x73 && flags & 1 != 0) || (kind == 0x74 && flags & 3 != 0) {
                return Err(blocked("multipart RAR unsupported"));
            }
            if flags & 0x8000 != 0 {
                data_size = u32le(&header, 7)? as u64;
            }
            if [0x74, 0x7a].contains(&kind) && flags & 0x100 != 0 {
                if header_size < 40 {
                    return Err(blocked("truncated RAR large-file header"));
                }
                data_size |= (u32le(&header, 32)? as u64) << 32;
            }
            if kind == 0x74 {
                if header_size < 32 {
                    return Err(blocked("truncated RAR file header"));
                }
                let mut unpacked = u32le(&header, 11)? as u64;
                if flags & 0x100 != 0 {
                    unpacked |= (u32le(&header, 36)? as u64) << 32;
                }
                members.push(Member {
                    size: unpacked,
                    crc: Some(u32le(&header, 16)?),
                    packed: data_size,
                });
            }
            end = kind == 0x7b;
            if end && flags & 1 != 0 {
                return Err(blocked("multipart RAR unsupported"));
            }
            if !(0x73..0x7c).contains(&kind) {
                return Err(blocked("unsupported RAR block"));
            }
        } else {
            let mut offset = 4;
            let header_data = vint(&prefix, &mut offset)?;
            if offset > 7 || header_data > 2 * MIB {
                return Err(blocked("invalid RAR5 header size"));
            }
            header_size = offset + header_data as usize;
            let header = read(file, position, header_size)?;
            if header.len() != header_size || crc32fast::hash(&header[4..]) != u32le(&header, 0)? {
                return Err(blocked("RAR5 header checksum/truncation error"));
            }
            let kind = vint(&header, &mut offset)?;
            if kind == 4 {
                return Err(blocked("encrypted RAR5 headers unsupported"));
            }
            if number == 0 && kind != 1 {
                return Err(blocked("invalid RAR5 main header"));
            }
            let flags = vint(&header, &mut offset)?;
            if flags & 0x18 != 0 {
                return Err(blocked("multipart RAR5 unsupported"));
            }
            let extra = if flags & 1 != 0 {
                vint(&header, &mut offset)?
            } else {
                0
            };
            if flags & 2 != 0 {
                data_size = vint(&header, &mut offset)?;
            }
            if extra > header.len().saturating_sub(offset) as u64 {
                return Err(blocked("invalid RAR5 extra area"));
            }
            if kind == 2 && extra > 0 {
                let mut extra_offset = header.len() - extra as usize;
                while extra_offset < header.len() {
                    let record_size = vint(&header, &mut extra_offset)?;
                    let end = extra_offset
                        .checked_add(record_size as usize)
                        .filter(|end| *end <= header.len())
                        .ok_or_else(|| blocked("invalid RAR5 extra record"))?;
                    if record_size == 0 {
                        return Err(blocked("empty RAR5 extra record"));
                    }
                    let record = vint(&header[..end], &mut extra_offset)?;
                    if record == 1 {
                        return Err(blocked("encrypted RAR5 member unsupported"));
                    }
                    extra_offset = end;
                }
            }
            if kind == 1 && vint(&header, &mut offset)? & 3 != 0 {
                return Err(blocked("multipart RAR5 unsupported"));
            }
            if kind == 2 {
                let flags = vint(&header, &mut offset)?;
                let unpacked = vint(&header, &mut offset)?;
                let _attrs = vint(&header, &mut offset)?;
                if flags & 8 != 0 {
                    return Err(blocked("RAR5 member has no declared size"));
                }
                if flags & 2 != 0 {
                    offset += 4;
                }
                let checksum = if flags & 4 != 0 {
                    Some(u32le(&header, offset)?)
                } else {
                    if flags & 1 == 0 {
                        return Err(blocked("RAR5 file requires CRC32 checksum"));
                    }
                    None
                };
                members.push(Member {
                    size: unpacked,
                    crc: checksum,
                    packed: data_size,
                });
            }
            end = kind == 5;
            if end && vint(&header, &mut offset)? & 1 != 0 {
                return Err(blocked("multipart RAR5 unsupported"));
            }
            if ![1, 2, 3, 5].contains(&kind) {
                return Err(blocked("unsupported RAR5 block"));
            }
        }
        position = position
            .checked_add(header_size as u64)
            .and_then(|p| p.checked_add(data_size))
            .filter(|p| *p <= size)
            .ok_or_else(|| blocked("RAR member data is truncated"))?;
        if end {
            if position != size {
                return Err(blocked("RAR trailing data after end marker"));
            }
            return Ok(Some(members));
        }
    }
    Err(blocked("RAR header count exceeds policy"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zip_requires_complete_end_record() {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"PK\x03\x04junk").unwrap();
        assert!(validate(&f, Format::Zip, 10).is_err());
    }
    #[test]
    fn malformed_variable_integers_fail() {
        assert!(vint(&[128; 10], &mut 0).is_err());
        assert!(vint(&[], &mut 0).is_err());
        assert_eq!(vint(&[0x81, 1], &mut 0).unwrap(), 129);
    }
}
