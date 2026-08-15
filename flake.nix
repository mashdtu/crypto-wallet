{
  description = "Bitcoin testnet wallet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs   = nixpkgs.legacyPackages.${system};

      # libwally-core is not in nixpkgs, so build it from the official release tarball.
      libwally-core = pkgs.stdenv.mkDerivation {
        pname   = "libwally-core";
        version = "1.3.1";

        src = pkgs.fetchzip {
          url    = "https://github.com/ElementsProject/libwally-core/archive/refs/tags/release_1.3.1.tar.gz";
          sha256 = "1dhlm1jlyhy0zg9ycwrhzwvqjkqic68cssl6602zr2mwhghr7f3w";
        };

        nativeBuildInputs = [
          pkgs.autoconf
          pkgs.automake
          pkgs.libtool
          pkgs.pkg-config
        ];

        preConfigure = ''
          ./tools/autogen.sh
        '';

        configureFlags = [
          "--disable-tests"
          "--disable-elements"
        ];
      };

    in {
      devShells.${system}.default = pkgs.mkShell {
        name = "btc-wallet-dev";

        buildInputs = [
          libwally-core        # BIP-39, BIP-32, PSBT, secp256k1
          pkgs.openssl         # SHA-256 via <openssl/sha.h>
          pkgs.pkg-config
          pkgs.gcc
          pkgs.gdb
          pkgs.valgrind
          pkgs.bear            # generates compile_commands.json for VS Code IntelliSense
        ];

        shellHook = ''
          echo ""
          echo "btc-wallet dev shell (testnet)"
          echo "  openssl  $(pkg-config --modversion openssl 2>/dev/null)"
          echo "  gcc      $(gcc --version | head -1)"
          echo ""
          echo "  make compile_commands  — fix VS Code IntelliSense (run once)"
          echo ""
        '';
      };
    };
}
