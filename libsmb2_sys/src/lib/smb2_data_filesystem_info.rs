mod ffi {
    #![allow(
        dead_code,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSizeInfo {
    pub total_allocation_units: u64,
    pub available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsDeviceInfo {
    pub device_type: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsVolumeInfo {
    pub creation_time_seconds: i64,
    pub creation_time_microseconds: i64,
    pub volume_serial_number: u32,
    pub supports_objects: u8,
    pub reserved: u8,
    pub volume_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsAttributeInfo {
    pub filesystem_attributes: u32,
    pub maximum_component_name_length: u32,
    pub filesystem_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsControlInfo {
    pub free_space_start_filtering: u64,
    pub free_space_threshold: u64,
    pub free_space_stop_filtering: u64,
    pub default_quota_threshold: u64,
    pub default_quota_limit: u64,
    pub file_system_control_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsFullSizeInfo {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsObjectIdInfo {
    pub object_id: [u8; 16],
    pub extended_info: [u8; 48],
}

pub fn decode_size(buf: &[u8]) -> Result<FsSizeInfo, i32> {
    let mut out = ffi::fs_size_info_ffi {
        total_allocation_units: 0,
        available_allocation_units: 0,
        sectors_per_allocation_unit: 0,
        bytes_per_sector: 0,
    };
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_size(buf.as_ptr(), buf.len(), &mut out)
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsSizeInfo {
        total_allocation_units: out.total_allocation_units,
        available_allocation_units: out.available_allocation_units,
        sectors_per_allocation_unit: out.sectors_per_allocation_unit,
        bytes_per_sector: out.bytes_per_sector,
    })
}

pub fn encode_size(info: FsSizeInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let raw = ffi::fs_size_info_ffi {
        total_allocation_units: info.total_allocation_units,
        available_allocation_units: info.available_allocation_units,
        sectors_per_allocation_unit: info.sectors_per_allocation_unit,
        bytes_per_sector: info.bytes_per_sector,
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_size(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_device(buf: &[u8]) -> Result<FsDeviceInfo, i32> {
    let mut out = ffi::fs_device_info_ffi {
        device_type: 0,
        characteristics: 0,
    };
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_device(buf.as_ptr(), buf.len(), &mut out)
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsDeviceInfo {
        device_type: out.device_type,
        characteristics: out.characteristics,
    })
}

pub fn encode_device(info: FsDeviceInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let raw = ffi::fs_device_info_ffi {
        device_type: info.device_type,
        characteristics: info.characteristics,
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_device(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_volume(buf: &[u8]) -> Result<FsVolumeInfo, i32> {
    let mut out = ffi::fs_volume_info_ffi {
        creation_time_seconds: 0,
        creation_time_microseconds: 0,
        volume_serial_number: 0,
        supports_objects: 0,
        reserved: 0,
        volume_label: std::ptr::null(),
    };
    let mut label = vec![0_i8; buf.len().saturating_add(1)];
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_volume(
            buf.as_ptr(),
            buf.len(),
            &mut out,
            label.as_mut_ptr(),
            label.len(),
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsVolumeInfo {
        creation_time_seconds: out.creation_time_seconds,
        creation_time_microseconds: out.creation_time_microseconds,
        volume_serial_number: out.volume_serial_number,
        supports_objects: out.supports_objects,
        reserved: out.reserved,
        volume_label: c_string(out.volume_label),
    })
}

pub fn encode_volume(info: &FsVolumeInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let label = std::ffi::CString::new(info.volume_label.as_str()).map_err(|_| -1)?;
    let raw = ffi::fs_volume_info_ffi {
        creation_time_seconds: info.creation_time_seconds,
        creation_time_microseconds: info.creation_time_microseconds,
        volume_serial_number: info.volume_serial_number,
        supports_objects: info.supports_objects,
        reserved: info.reserved,
        volume_label: label.as_ptr(),
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_volume(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_attribute(buf: &[u8]) -> Result<FsAttributeInfo, i32> {
    let mut out = ffi::fs_attribute_info_ffi {
        filesystem_attributes: 0,
        maximum_component_name_length: 0,
        filesystem_name: std::ptr::null(),
    };
    let mut name = vec![0_i8; buf.len().saturating_add(1)];
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_attribute(
            buf.as_ptr(),
            buf.len(),
            &mut out,
            name.as_mut_ptr(),
            name.len(),
        )
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsAttributeInfo {
        filesystem_attributes: out.filesystem_attributes,
        maximum_component_name_length: out.maximum_component_name_length,
        filesystem_name: c_string(out.filesystem_name),
    })
}

pub fn encode_attribute(info: &FsAttributeInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let name = std::ffi::CString::new(info.filesystem_name.as_str()).map_err(|_| -1)?;
    let raw = ffi::fs_attribute_info_ffi {
        filesystem_attributes: info.filesystem_attributes,
        maximum_component_name_length: info.maximum_component_name_length,
        filesystem_name: name.as_ptr(),
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_attribute(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_control(buf: &[u8]) -> Result<(FsControlInfo, i32), i32> {
    let mut out = ffi::fs_control_info_ffi {
        free_space_start_filtering: 0,
        free_space_threshold: 0,
        free_space_stop_filtering: 0,
        default_quota_threshold: 0,
        default_quota_limit: 0,
        file_system_control_flags: 0,
    };
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_control(buf.as_ptr(), buf.len(), &mut out)
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok((
        FsControlInfo {
            free_space_start_filtering: out.free_space_start_filtering,
            free_space_threshold: out.free_space_threshold,
            free_space_stop_filtering: out.free_space_stop_filtering,
            default_quota_threshold: out.default_quota_threshold,
            default_quota_limit: out.default_quota_limit,
            file_system_control_flags: out.file_system_control_flags,
        },
        rc,
    ))
}

pub fn encode_control(info: FsControlInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let raw = ffi::fs_control_info_ffi {
        free_space_start_filtering: info.free_space_start_filtering,
        free_space_threshold: info.free_space_threshold,
        free_space_stop_filtering: info.free_space_stop_filtering,
        default_quota_threshold: info.default_quota_threshold,
        default_quota_limit: info.default_quota_limit,
        file_system_control_flags: info.file_system_control_flags,
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_control(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_full_size(buf: &[u8]) -> Result<FsFullSizeInfo, i32> {
    let mut out = ffi::fs_full_size_info_ffi {
        total_allocation_units: 0,
        caller_available_allocation_units: 0,
        actual_available_allocation_units: 0,
        sectors_per_allocation_unit: 0,
        bytes_per_sector: 0,
    };
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_full_size(buf.as_ptr(), buf.len(), &mut out)
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsFullSizeInfo {
        total_allocation_units: out.total_allocation_units,
        caller_available_allocation_units: out.caller_available_allocation_units,
        actual_available_allocation_units: out.actual_available_allocation_units,
        sectors_per_allocation_unit: out.sectors_per_allocation_unit,
        bytes_per_sector: out.bytes_per_sector,
    })
}

pub fn encode_full_size(info: FsFullSizeInfo, out_len: usize) -> Result<(Vec<u8>, i32), i32> {
    let raw = ffi::fs_full_size_info_ffi {
        total_allocation_units: info.total_allocation_units,
        caller_available_allocation_units: info.caller_available_allocation_units,
        actual_available_allocation_units: info.actual_available_allocation_units,
        sectors_per_allocation_unit: info.sectors_per_allocation_unit,
        bytes_per_sector: info.bytes_per_sector,
    };
    encode(out_len, |buf| unsafe {
        ffi::smb2_data_filesystem_info_ffi_encode_full_size(&raw, buf.as_mut_ptr(), buf.len())
    })
}

pub fn decode_object_id(buf: &[u8]) -> Result<FsObjectIdInfo, i32> {
    let mut out = ffi::fs_object_id_info_ffi {
        object_id: [0; 16],
        extended_info: [0; 48],
    };
    let rc = unsafe {
        ffi::smb2_data_filesystem_info_ffi_decode_object_id(buf.as_ptr(), buf.len(), &mut out)
    };
    if rc < 0 {
        return Err(rc);
    }
    Ok(FsObjectIdInfo {
        object_id: out.object_id,
        extended_info: out.extended_info,
    })
}

fn encode(out_len: usize, f: impl FnOnce(&mut Vec<u8>) -> i32) -> Result<(Vec<u8>, i32), i32> {
    let mut buf = vec![0; out_len];
    let rc = f(&mut buf);
    if rc < 0 {
        return Err(rc);
    }
    Ok((buf, rc))
}

fn c_string(ptr: *const i8) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
