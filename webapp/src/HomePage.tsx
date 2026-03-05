import { Link } from 'react-router-dom';
import { Card } from 'antd';
import { HeartOutlined, SafetyOutlined } from '@ant-design/icons';

export function HomePage() {
  return (
    <div className="max-w-[1200px] mx-auto p-8">
      <h1 className="text-[28px] font-bold text-white mb-6">Dashboard</h1>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-4">
        <Link to="/fleetwood" className="no-underline">
          <Card hoverable className="!bg-[#1e293b] !border-[#334155]">
            <div className="flex items-center gap-3 mb-2">
              <HeartOutlined className="text-xl text-sky-400" />
              <span className="text-lg font-semibold text-sky-400">Health</span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed m-0">
              BackendDB cluster health, node metrics, and map statistics
            </p>
          </Card>
        </Link>
        <Link to="/queen" className="no-underline">
          <Card hoverable className="!bg-[#1e293b] !border-[#334155]">
            <div className="flex items-center gap-3 mb-2">
              <SafetyOutlined className="text-xl text-sky-400" />
              <span className="text-lg font-semibold text-sky-400">API &amp; Entitlements</span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed m-0">
              Entitlements catalog, policy simulator, and OPA tester
            </p>
          </Card>
        </Link>
      </div>
    </div>
  );
}
