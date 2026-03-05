import { useState } from 'react';
import { Modal, Button, Segmented, Space, Typography } from 'antd';
import { CopyOutlined, DownloadOutlined, LinkOutlined, CheckOutlined } from '@ant-design/icons';
import { parseJwt, getStoredToken, getStoredRefreshToken, type JwtPayload } from './tokenUtils';

const { Text } = Typography;

interface TokenModalProps {
  onClose: () => void;
}

type Tab = 'access' | 'refresh';

export function TokenModal({ onClose }: TokenModalProps) {
  const [tab, setTab] = useState<Tab>('access');
  const [copied, setCopied] = useState(false);

  const accessToken = getStoredToken();
  const refreshToken = getStoredRefreshToken();
  const token = tab === 'access' ? accessToken : refreshToken;
  const payload = token ? parseJwt(token) : null;

  const handleCopy = async () => {
    if (!token) return;
    await navigator.clipboard.writeText(token);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenJwtIo = () => {
    if (!token) return;
    window.open(`https://jwt.io/#debugger-io?token=${token}`, '_blank');
  };

  const handleDownload = () => {
    if (!token) return;
    const blob = new Blob([token], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${tab}_token.jwt`;
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  const formatExpiry = (payload: JwtPayload | null): string => {
    if (!payload?.exp) return 'unknown';
    const exp = new Date(payload.exp * 1000);
    const now = Date.now();
    const diff = payload.exp * 1000 - now;
    if (diff <= 0) return `expired (${exp.toLocaleTimeString()})`;
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    if (mins > 60) {
      const hours = Math.floor(mins / 60);
      return `${hours}h ${mins % 60}m remaining`;
    }
    return `${mins}m ${secs}s remaining`;
  };

  return (
    <Modal
      title="JWT Token"
      open
      onCancel={onClose}
      width={640}
      footer={
        token ? (
          <Space>
            <Button
              icon={copied ? <CheckOutlined /> : <CopyOutlined />}
              onClick={handleCopy}
            >
              {copied ? 'Copied!' : 'Copy Token'}
            </Button>
            <Button icon={<LinkOutlined />} onClick={handleOpenJwtIo}>
              jwt.io
            </Button>
            <Button icon={<DownloadOutlined />} onClick={handleDownload}>
              Download
            </Button>
          </Space>
        ) : null
      }
    >
      <Segmented
        value={tab}
        onChange={(val) => setTab(val as Tab)}
        options={[
          { label: 'Access Token', value: 'access' },
          { label: 'Refresh Token', value: 'refresh' },
        ]}
        className="mb-3"
      />

      {payload && (
        <Text type="secondary" className="block mb-3 text-xs">
          {formatExpiry(payload)}
        </Text>
      )}

      {payload ? (
        <pre className="bg-[#0f172a] rounded-md p-4 overflow-auto max-h-[50vh] text-[13px] leading-relaxed font-mono text-slate-200 m-0">
          {syntaxHighlight(JSON.stringify(payload, null, 2))}
        </pre>
      ) : (
        <div className="text-center py-10 text-slate-500 text-sm">
          No {tab} token available
        </div>
      )}
    </Modal>
  );
}

function syntaxHighlight(json: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  let i = 0;

  const escaped = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const regex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g;

  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(escaped)) !== null) {
    if (match.index > lastIndex) {
      parts.push(escaped.slice(lastIndex, match.index));
    }

    let color: string;
    const m = match[0];
    if (/^"/.test(m)) {
      color = /:$/.test(m) ? '#38bdf8' : '#4ade80';
    } else if (/true|false/.test(m)) {
      color = '#f472b6';
    } else if (/null/.test(m)) {
      color = '#a78bfa';
    } else {
      color = '#fbbf24';
    }

    parts.push(
      <span key={i++} style={{ color }}>{m}</span>
    );
    lastIndex = regex.lastIndex;
  }

  if (lastIndex < escaped.length) {
    parts.push(escaped.slice(lastIndex));
  }

  return parts;
}
