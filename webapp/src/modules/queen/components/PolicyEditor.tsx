import { Button, Input, Spin } from 'antd';

const { TextArea } = Input;

interface Props {
  policy: string;
  loading: boolean;
  onChange: (value: string) => void;
  onReset: () => void;
}

export function PolicyEditor({ policy, loading, onChange, onReset }: Props) {
  if (loading) {
    return <div className="text-center py-6"><Spin tip="Loading policy..." /></div>;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-base font-bold text-slate-200">Entitlements Policy</span>
        <Button size="small" onClick={onReset}>Reset to deployed</Button>
      </div>

      <p className="text-[13px] text-slate-500 mb-4 mt-0">
        Edit the OPA Rego policy to simulate different authorization rules. Changes auto-update the API Catalog.
      </p>

      <TextArea
        value={policy}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
        autoSize={{ minRows: 12 }}
        className="!bg-[#0f172a] !border-[#334155] !text-slate-200 font-mono text-[13px]"
      />
    </div>
  );
}
