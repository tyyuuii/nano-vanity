//! Phase 0 probe: is a Vulkan compute device actually reachable from Termux?
//!
//! This is the cheapest decisive check in the GPU plan. Everything downstream --
//! field arithmetic, scalar multiply, engine integration -- is pointless if we
//! cannot enumerate a device, or if the device has no compute queue.
//!
//! Run: `cargo run --release --example gpu_probe`

use ash::{vk, Entry};

/// Android ships `/system/lib64/libvulkan.so` but *not* `libvulkan.so.1`,
/// which is the name `ash::Entry::load()` tries by default. So we try the
/// absolute Android path first and fall back to the conventional lookup.
fn load_entry() -> Result<(Entry, &'static str), String> {
    let candidates = [
        "/system/lib64/libvulkan.so",
        "libvulkan.so.1",
        "libvulkan.so",
    ];
    let mut last = String::new();
    for path in candidates {
        match unsafe { Entry::load_from(path) } {
            Ok(entry) => return Ok((entry, path)),
            Err(e) => last = format!("{path}: {e}"),
        }
    }
    Err(format!("could not load Vulkan loader. tried: {last}"))
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn main() {
    println!("=== nano-vanity GPU probe (Phase 0) ===\n");

    let (entry, path) = match load_entry() {
        Ok(v) => v,
        Err(e) => {
            println!("FAIL  {e}");
            println!("\nVerdict: no Vulkan loader. GPU path is dead at step 0.");
            std::process::exit(1);
        }
    };
    println!("  loader            {path}");

    // Request Vulkan 1.1 when the loader offers it: the subgroup query below
    // goes through the *core 1.1* entry point, not the KHR extension. This
    // vendor driver reports 1.1.0 but does not expose the _khr alias, and ash
    // aborts the process when an extern fn cannot be resolved -- so asking for
    // 1.0 here would make the subgroup query a hard crash.
    let inst_ver = unsafe { entry.try_enumerate_instance_version() }.unwrap_or(None);
    let app_api = match inst_ver {
        Some(v) if vk::api_version_minor(v) >= 1 => vk::API_VERSION_1_1,
        _ => vk::API_VERSION_1_0,
    };
    match inst_ver {
        Some(v) => println!(
            "  instance version  {}.{}.{}",
            vk::api_version_major(v),
            vk::api_version_minor(v),
            vk::api_version_patch(v)
        ),
        None => println!("  instance version  1.0 (loader reports 1.0 only)"),
    }

    let app = vk::ApplicationInfo::default()
        .application_name(c"nano-vanity-gpu-probe")
        .application_version(0)
        .engine_name(c"nano-vanity")
        .engine_version(0)
        .api_version(app_api);
    let ci = vk::InstanceCreateInfo::default().application_info(&app);

    let instance = match unsafe { entry.create_instance(&ci, None) } {
        Ok(i) => i,
        Err(e) => {
            println!("FAIL  create_instance: {e}");
            println!("\nVerdict: loader present, instance refused. GPU path is dead at step 0.");
            std::process::exit(1);
        }
    };
    println!("  instance          created\n");

    let has_1_1 = app_api >= vk::API_VERSION_1_1;

    let devices = match unsafe { instance.enumerate_physical_devices() } {
        Ok(d) => d,
        Err(e) => {
            println!("FAIL  enumerate_physical_devices: {e}");
            std::process::exit(1);
        }
    };
    if devices.is_empty() {
        println!("FAIL  enumerate_physical_devices returned 0 devices");
        println!("\nVerdict: no Vulkan device. GPU path is dead at step 0.");
        std::process::exit(1);
    }
    println!("  devices           {}\n", devices.len());

    let mut any_compute = false;
    for (i, dev) in devices.iter().enumerate() {
        let props = unsafe { instance.get_physical_device_properties(*dev) };
        let api = props.api_version;
        let dtype = match props.device_type {
            vk::PhysicalDeviceType::DISCRETE_GPU => "discrete",
            vk::PhysicalDeviceType::INTEGRATED_GPU => "integrated",
            vk::PhysicalDeviceType::VIRTUAL_GPU => "virtual",
            _ => "other/CPU",
        };
        println!("  device[{i}] {}", cstr(&props.device_name));
        println!("    type            {dtype}");
        println!(
            "    api             {}.{}.{}",
            vk::api_version_major(api),
            vk::api_version_minor(api),
            vk::api_version_patch(api)
        );
        println!(
            "    driver          {}.{}.{}",
            vk::api_version_major(props.driver_version),
            vk::api_version_minor(props.driver_version),
            vk::api_version_patch(props.driver_version)
        );

        let qf = unsafe { instance.get_physical_device_queue_family_properties(*dev) };
        let mut compute = Vec::new();
        for (qi, q) in qf.iter().enumerate() {
            if q.queue_flags.contains(vk::QueueFlags::COMPUTE) {
                compute.push(qi);
                let extra = if q.queue_flags.contains(vk::QueueFlags::GRAPHICS) {
                    "  (graphics+compute)"
                } else {
                    ""
                };
                println!(
                    "    queue family {qi}  count={}  flags=0x{:x}{extra}",
                    q.queue_count,
                    q.queue_flags.as_raw()
                );
            }
        }
        if compute.is_empty() {
            println!("    queue families   NO COMPUTE QUEUE");
        } else {
            any_compute = true;
            println!("    compute usable   yes ({} families)", compute.len());
        }

        // Subgroup size is the key Mali tuning fact: the plan assumes 4. It
        // comes back through the core 1.1 pNext chain. If the loader is 1.0
        // this is skipped rather than fatal -- we can measure subgroup size
        // empirically in the throughput benchmark instead.
        if has_1_1 {
            let mut sub = vk::PhysicalDeviceSubgroupProperties::default();
            let mut p2 = vk::PhysicalDeviceProperties2::default().push_next(&mut sub);
            unsafe { instance.get_physical_device_properties2(*dev, &mut p2) };
            println!("    subgroup size    {}", sub.subgroup_size);
            println!(
                "    subgroup stages  0x{:x}  (bit0=compute)",
                sub.supported_stages.as_raw()
            );
            // bit5 = SHADD (INT32 add), bit9 = SHADDD. INT32 add is what a
            // field-arithmetic kernel leans on most.
            println!(
                "    subgroup ops     0x{:x}  (bit5=INT32 add, bit9=INT64 add)",
                sub.supported_operations.as_raw()
            );
        } else {
            println!("    subgroup size    not queried (loader is Vulkan 1.0)");
        }

        let l = props.limits;
        println!("    max wg invocations   {}", l.max_compute_work_group_invocations);
        println!(
            "    max wg size          {} x {} x {}",
            l.max_compute_work_group_size[0],
            l.max_compute_work_group_size[1],
            l.max_compute_work_group_size[2]
        );
        println!(
            "    max wg count         {} x {} x {}",
            l.max_compute_work_group_count[0],
            l.max_compute_work_group_count[1],
            l.max_compute_work_group_count[2]
        );
        println!("    shared mem           {}", l.max_compute_shared_memory_size);
        println!("    max storage buf      {}", l.max_storage_buffer_range);
        println!("    timestampPeriod      {}", l.timestamp_period);
        println!();
    }

    unsafe { instance.destroy_instance(None) };

    println!("--- Phase 0 gate 0a: is a compute device reachable? ---");
    if any_compute {
        println!("PASS  a compute queue family is present.");
        println!("      next: compile a SPIR-V compute shader and measure INT32 throughput");
        println!("            against a NEON baseline (gate 0b).");
    } else {
        println!("FAIL  no compute queue. Stop here; no shader work is worth doing.");
        std::process::exit(1);
    }
}
