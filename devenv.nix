{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{

  #
  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.sops pkgs.age pkgs.gum pkgs.mold ];
  dotenv.enable = true;

  # enable nightly rust
  # languages.rust.enable = true;
  # languages.rust.channel = "nightly";
  # languages.rust.mold.enable = true;
  # languages.rust.targets = [ "x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl" ];
  # languages.rust.components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "miri" "rust-src" ];


  # disable mcp


  # https://devenv.sh/languages/
  # languages.rust.enable = true;

  # https://devenv.sh/processes/
  # processes.dev.exec = "${lib.getExe pkgs.watchexec} -n -- ls -la";

  # https://devenv.sh/services/
  # services.postgres.enable = true;

  # https://devenv.sh/scripts/

  # https://devenv.sh/git-hooks/
  # git-hooks.hooks.shellcheck.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
