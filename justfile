# Local development builds only — not used in CI/CD.

src_flag := if path_exists("../../proto") == "true" { "--src ../../proto" } else { "" }
mount_flag := if path_exists("../../utils") == "true" { "--mount ../../utils:/utils" } else { "" }

default:
  tacplus build {{src_flag}} {{mount_flag}}

verify:
  tacplus verify

clean:
  rm -rf target
