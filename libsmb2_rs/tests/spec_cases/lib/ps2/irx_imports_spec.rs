use libsmb2_rs::lib::ps2::irx_imports::{imports, IrxImport};

// Trace: `lib/ps2/irx_imports.h:16`, `lib/ps2/irx_imports.h:18`, `lib/ps2/irx_imports.h:19`, `lib/ps2/irx_imports.h:20`, `lib/ps2/irx_imports.h:21`, `lib/ps2/irx_imports.h:22`, `lib/ps2/irx_imports.h:23`, `lib/ps2/irx_imports.h:24`, `lib/ps2/irx_imports.h:25`, `lib/ps2/irx_imports.h:26`
// Spec: irx_imports.h include surface exposes PS2 IOP imports#include header once
// - **GIVEN** PS2 IOP 编译环境提供 `irx.h`、`intrman.h`、`ioman.h`、`ps2ip.h`、`sifman.h`、`stdio.h`、`sysclib.h`、`sysmem.h`、`thbase.h` 和 `thsemap.h`
// - **WHEN** 调用方包含 `lib/ps2/irx_imports.h`
// - **THEN** 编译单元获得这些 PS2SDK import 头文件声明，且该头文件自身不定义额外函数、类型或资源生命周期行为
#[test]
fn test_irx_imports_include_header_once() {
    assert_eq!(
        imports(),
        [
            IrxImport::Intrman,
            IrxImport::Ioman,
            IrxImport::Ps2ip,
            IrxImport::Sifman,
            IrxImport::Stdio,
            IrxImport::Sysclib,
            IrxImport::Sysmem,
            IrxImport::Thbase,
            IrxImport::Thsemap,
        ]
    );
}

// Trace: `lib/ps2/irx_imports.h:13`, `lib/ps2/irx_imports.h:14`, `lib/ps2/irx_imports.h:28`
// Spec: irx_imports.h include surface exposes PS2 IOP imports#include header repeatedly
// - **GIVEN** 一个编译单元已展开过 `lib/ps2/irx_imports.h` 并定义 `IOP_IRX_IMPORTS_H`
// - **WHEN** 同一编译单元再次包含 `lib/ps2/irx_imports.h`
// - **THEN** 头文件主体不会重复展开 PS2SDK IOP import includes
#[test]
fn test_irx_imports_include_header_repeatedly() {
    assert_eq!(imports(), imports());
    assert_eq!(imports().len(), 9);
}
