use super::*;

#[test]
fn unmirror_roundtrip_file() {
    let root = PathBuf::from(r"D:\sb");
    let virtual_dos = r"c:\users\alice\file.txt";
    let overlay = mirror_into_overlay(virtual_dos, &root);
    assert_eq!(overlay, PathBuf::from(r"D:\sb\c\users\alice\file.txt"));
    let back = unmirror_from_overlay(&overlay, &root).unwrap();
    assert_eq!(back, virtual_dos);
}

#[test]
fn unmirror_drive_root_only() {
    let root = PathBuf::from(r"D:\sb");
    let overlay = mirror_into_overlay(r"d:\", &root);
    let back = unmirror_from_overlay(&overlay, &root).unwrap();
    assert_eq!(back, r"d:");
}

#[test]
fn unmirror_not_under_root_returns_none() {
    let root = PathBuf::from(r"D:\sb");
    let alien = PathBuf::from(r"D:\elsewhere\c\file.txt");
    assert!(unmirror_from_overlay(&alien, &root).is_none());
}

#[test]
fn unmirror_first_component_not_drive_letter() {
    let root = PathBuf::from(r"D:\sb");
    // "cd" is two chars — not a drive letter.
    let overlay = PathBuf::from(r"D:\sb\cd\file.txt");
    assert!(unmirror_from_overlay(&overlay, &root).is_none());
}

#[test]
fn mirror_unmirror_case_preserved() {
    // mirror_into_overlay preserves case of the components (only strips ':');
    // unmirror_from_overlay does not lowercase. The virtual DOS path roundtrips.
    let root = PathBuf::from(r"D:\sb");
    let virtual_dos = r"D:\Users\Alice";
    let overlay = mirror_into_overlay(virtual_dos, &root);
    let back = unmirror_from_overlay(&overlay, &root).unwrap();
    assert_eq!(back, virtual_dos);
}

#[test]
fn dos_to_volume_relative_strips_drive_letter() {
    assert_eq!(dos_to_volume_relative(r"d:\proj\.git\HEAD"), r"\proj\.git\HEAD");
    assert_eq!(dos_to_volume_relative(r"D:\proj"), r"\proj");
    assert_eq!(dos_to_volume_relative(r"c:\"), r"\");
}

#[test]
fn dos_to_volume_relative_passthrough_without_drive() {
    assert_eq!(dos_to_volume_relative(r"\already\relative"), r"\already\relative");
    assert_eq!(dos_to_volume_relative(r"bare"), r"bare");
    assert_eq!(dos_to_volume_relative(""), "");
}

#[test]
fn unmirror_then_volume_relative_roundtrip() {
    // Full round-trip: virtual DOS → overlay → unmirror → strip drive.
    // The volume-relative form is what FileNameInformation must return.
    let root = PathBuf::from(r"C:\Users\me\.winrsbox\sbx\workdir");
    let virtual_dos = r"d:\proj\.git\HEAD";
    let overlay = mirror_into_overlay(virtual_dos, &root);
    let back = unmirror_from_overlay(&overlay, &root).unwrap();
    let vol_rel = dos_to_volume_relative(&back);
    assert_eq!(vol_rel, r"\proj\.git\HEAD");
}

// ── OverlayLayout (same-volume) tests ──────────────────────────────────

#[test]
fn layout_single_uses_primary_root() {
    // No per-drive overrides → every drive uses primary_root.
    let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
    assert_eq!(layout.root_for(r"c:\users\me"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
    assert_eq!(layout.root_for(r"d:\foo"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
}

#[test]
fn layout_per_drive_override_for_c() {
    // C: has an explicit same-volume root (on C:); D: falls back to primary.
    let layout = OverlayLayout::new(
        PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
        [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
    );
    assert_eq!(layout.root_for(r"c:\users\me\appdata"), Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"));
    assert_eq!(layout.root_for(r"d:\proj"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
    // case-insensitive drive match
    assert_eq!(layout.root_for(r"C:\Users"), Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"));
}

#[test]
fn layout_mirror_roundtrip_c_drive() {
    // mirror c:\... → C:-root overlay (same volume); unmirror recovers c:\...
    let layout = OverlayLayout::new(
        PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
        [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
    );
    let virtual_dos = r"c:\users\me\appdata\local\clonebug";
    let overlay = mirror_into_overlay_layout(virtual_dos, &layout);
    // Must live on C: (same volume as virtual) — NOT on D:.
    assert!(overlay.starts_with(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"),
        "C: overlay must be on C: volume, got {}", overlay.display());
    assert_eq!(overlay, Path::new(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir\users\me\appdata\local\clonebug"));
    let back = unmirror_from_overlay_layout(&overlay, &layout).unwrap();
    assert_eq!(back, r"c:\users\me\appdata\local\clonebug");
}

#[test]
fn layout_mirror_roundtrip_d_drive_uses_primary() {
    // d:\... has no override → uses primary_root (which is on D:).
    let layout = OverlayLayout::new(
        PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"),
        [('c', PathBuf::from(r"C:\Users\me\AppData\Local\.winrsbox\sbx\workdir"))],
    );
    let virtual_dos = r"d:\proj\repo\.git\HEAD";
    let overlay = mirror_into_overlay_layout(virtual_dos, &layout);
    assert!(overlay.starts_with(r"D:\proj\.winrsbox\sbx\workdir"));
    let back = unmirror_from_overlay_layout(&overlay, &layout).unwrap();
    assert_eq!(back, r"d:\proj\repo\.git\HEAD");
}

#[test]
fn layout_unmirror_unknown_path_returns_none() {
    let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
    let alien = Path::new(r"E:\unrelated\path");
    assert!(unmirror_from_overlay_layout(alien, &layout).is_none());
}

#[test]
fn layout_no_drive_letter_uses_primary() {
    // A path with no leading drive letter falls back to primary_root.
    let layout = OverlayLayout::single(PathBuf::from(r"D:\proj\.winrsbox\sbx\workdir"));
    assert_eq!(layout.root_for(r"\relative\path"), Path::new(r"D:\proj\.winrsbox\sbx\workdir"));
}
