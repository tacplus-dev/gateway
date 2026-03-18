proto_dir := "../proto"

build:
  tacplus build --src {{proto_dir}}
  cargo build --release

check:
  tacplus build --src {{proto_dir}}
  cargo clippy -- -D warnings

run:
  cargo run

clean:
  cargo clean

docker:
  tacplus build --src {{proto_dir}}
  cargo build --release
  docker build -t gateway .
