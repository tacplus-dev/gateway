import { Button, Input } from 'antd';

const { TextArea } = Input;

function base64UrlDecode(s: string): string {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  return atob(padded);
}

function parseJwtParts(token: string): { header: string; payload: string } | null {
  try {
    const parts = token.trim().split('.');
    if (parts.length < 2) return null;
    const header = JSON.stringify(JSON.parse(base64UrlDecode(parts[0])), null, 2);
    const payload = JSON.stringify(JSON.parse(base64UrlDecode(parts[1])), null, 2);
    return { header, payload };
  } catch {
    return null;
  }
}

interface Props {
  headerJson: string;
  payloadJson: string;
  onHeaderChange: (value: string) => void;
  onPayloadChange: (value: string) => void;
  onReset: () => void;
}

export function TokenEditor({ headerJson, payloadJson, onHeaderChange, onPayloadChange, onReset }: Props) {
  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const text = e.clipboardData.getData('text').trim();
    const parts = parseJwtParts(text);
    if (parts) {
      e.preventDefault();
      onHeaderChange(parts.header);
      onPayloadChange(parts.payload);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-base font-bold text-slate-200">Bearer Token</span>
        <Button size="small" onClick={onReset}>Reset to real token</Button>
      </div>

      <p className="text-[13px] text-slate-500 mb-4 mt-0">
        Edit the payload to simulate different claims. Changes auto-update the API Catalog.
        Paste a full JWT to split into header + payload.
      </p>

      <div className="flex gap-4 mb-3">
        <div className="min-w-[240px]">
          <label className="block text-[13px] font-semibold text-slate-400 mb-1">Header (read-only)</label>
          <TextArea
            value={headerJson}
            readOnly
            spellCheck={false}
            autoSize={{ minRows: 3 }}
            className="!bg-[#0f172a] !border-[#334155] !text-slate-400 font-mono text-[13px] !cursor-default"
          />
        </div>
        <div className="flex-1">
          <label className="block text-[13px] font-semibold text-slate-400 mb-1">Payload (editable)</label>
          <TextArea
            value={payloadJson}
            onChange={(e) => onPayloadChange(e.target.value)}
            onPaste={handlePaste}
            spellCheck={false}
            autoSize={{ minRows: 3 }}
            className="!bg-[#0f172a] !border-[#334155] !text-slate-200 font-mono text-[13px]"
          />
        </div>
      </div>
    </div>
  );
}
