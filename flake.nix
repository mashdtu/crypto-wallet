{
  description = "Bitcoin testnet wallet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs   = nixpkgs.legacyPackages.${system};

    in {
      devShells.${system}.default = pkgs.mkShell {
        name = "btc-wallet-dev";

        buildInputs = [
          pkgs.openssl         # SHA-256, HMAC, PBKDF2
          pkgs.secp256k1       # EC key derivation, signing
          pkgs.pkg-config
          pkgs.gcc
          pkgs.gdb
          pkgs.valgrind
          pkgs.bear
          pkgs.util-linux      # wipefs for clearing USB partition tables
          pkgs.curl            # libcurl for mempool.space API queries
        ];

        shellHook = ''
          # NIX_LDFLAGS can carry stale -L paths from previous shells.
          # The Makefile uses pkg-config explicitly, so we don't need it.
          unset NIX_LDFLAGS

          echo ""
          echo "btc-wallet dev shell (testnet)"
          echo "  openssl  $(pkg-config --modversion openssl 2>/dev/null)"
          echo "  gcc      $(gcc --version | head -1)"
          echo ""
          echo "  make compile_commands - fix VS Code IntelliSense (run once)"
          echo ""
        '';
      };
    };
}
