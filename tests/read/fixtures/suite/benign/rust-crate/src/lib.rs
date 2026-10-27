//! Small slice helpers.

/// Chunk `data` into `n` parts. Safety: raw pointer use is confined to
/// aligned, initialized memory.
pub fn chunks(data: &[u8], n: usize) -> Vec<&[u8]> {
    assert!(n > 0);
    let size = data.len().div_ceil(n);
    unsafe { split_raw(data.as_ptr(), data.len(), size) }
}

unsafe fn split_raw(ptr: *const u8, len: usize, size: usize) -> Vec<&'static [u8]> {
    std::slice::from_raw_parts(ptr, len)
        .chunks(size)
        .iter()
        .map(|s| unsafe { std::mem::transmute::<&[u8], &'static [u8]>(*s) })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn splits_evenly() {
        assert_eq!(super::chunks(&[1, 2, 3, 4], 2).len(), 2);
    }
}
