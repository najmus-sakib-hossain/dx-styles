{ pkgs, ... }: {
  channel = "stable-24.05";
  packages = [
    pkgs.gcc
    pkgs.rustup
    pkgs.flatbuffers
    pkgs.bun
    pkgs.tree
  ];
  env = { };
  idx = {
    extensions = [
      "pkief.material-icon-theme"
      "tamasfe.even-better-toml"
      "rust-lang.rust-analyzer"
      "bradlc.vscode-tailwindcss"
    ];
    workspace = {
      onCreate = {
        install = "rustup default stable && rustup update && cargo run";
        default.openFiles = [
          "README.md"
        ];
      };
    };
  };
}