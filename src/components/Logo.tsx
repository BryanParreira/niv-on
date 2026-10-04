import logoUrl from "../../assets/logo.svg";

/** Niv.ON mark (glitched pixel "n" + live green pixel) — same artwork as the app icon. */
export function LogoMark({ size = 28 }: { size?: number }) {
  return <img src={logoUrl} width={size} height={size} alt="" style={{ display: "block", margin: -size * 0.1 }} />;
}

/** Wordmark: "Niv" + ".ON" in the condensed display face. */
export function Wordmark() {
  return (
    <span className="wordmark">
      Niv<span className="wordmark-on">.ON</span>
    </span>
  );
}
