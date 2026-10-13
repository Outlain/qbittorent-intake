# Notice files omitted from published crates

`valuable-0.1.1-LICENSE` is the verbatim upstream MIT notice at
<https://raw.githubusercontent.com/tokio-rs/valuable/9efc29b6e58cef28f6566a47aa7e142a55fead77/LICENSE>.
The published crate's `.cargo_vcs_info.json` identifies that exact commit and
its README links to the repository-root notice, which was not packaged.

The `winapi-i686-pc-windows-gnu` and `winapi-x86_64-pc-windows-gnu` 0.4.0 support
crates omit their notices too. The generator uses the MIT and Apache notices
from the locked parent `winapi` 0.3.9 crate in the same upstream project.
Those platform-specific support libraries are not part of the Linux images.

The generator also includes `r-efi`'s `AUTHORS`, which contains its copyright
and license grants. Other dependency notices come from their cached crate
sources. Public upstream author/copyright identities are retained as notices;
no local package-cache paths are written to the generated bundle.
