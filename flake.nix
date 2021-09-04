{
  description = "DNSSEC Offline KSK Ceremony Tools";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "aarch64-linux" "i686-linux" "x86_64-linux" ];

      forAllSystems = f:
        nixpkgs.lib.genAttrs supportedSystems (system: f system);

      nixpkgsFor = forAllSystems (system:
        import nixpkgs {
          inherit system;
          overlays = [ self.overlay ];
        });
    in
    {
      overlay = final: prev: with prev; {
        dnssec-ceremony-tools = stdenv.mkDerivation rec {
            pname = "dnssec-ceremony-tools";
            version = "unstable-2021-02-25";

            src = ./.;

            dontConfigure = true;
            dontBuild = true;

            propagatedBuildInputs = [
              python3Packages.hjson
              python3Packages.pyyaml
              python3Packages.python-pkcs11
            ];

            installPhase = ''
              substituteInPlace oks.py \
                --replace '/usr/bin/env python3' '${python3}/bin/python3'
              substituteInPlace oks.conf \
                --replace '/home/berry/nlnetlabs/dnssec-ceremony-tools/ROOT' '${softhsm}'
              mkdir -p $out/bin $out/share
              cp oks.py $out/bin
              cp oks.conf $out/share
            '';
          };
      };

      packages = forAllSystems (system: {
        inherit (nixpkgsFor.${system}) dnssec-ceremony-tools;
      });

      devShell = self.defaultPackage;

      defaultPackage = forAllSystems (system:
        self.packages.${system}.dnssec-ceremony-tools);
    };
}
