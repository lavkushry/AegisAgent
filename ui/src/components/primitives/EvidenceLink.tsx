import { Fingerprint } from "lucide-react";
import HashText from "./HashText";

export default function EvidenceLink({ hash, onClick }: { hash: string; onClick?: () => void }) {
  return <button type="button" onClick={onClick} disabled={!onClick} className="inline-flex items-center gap-2 text-[var(--brand)] disabled:cursor-default"><Fingerprint size={13} aria-hidden="true" /><HashText value={hash} /></button>;
}
