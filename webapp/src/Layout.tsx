import { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Layout as AntLayout, Menu, Button, Avatar } from 'antd';
import {
  HomeOutlined,
  HeartOutlined,
  SafetyOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from '@ant-design/icons';
import { useAuth } from './auth/useAuth';
import { TokenModal } from './auth/TokenModal';

const { Sider, Content } = AntLayout;

const menuItems = [
  { key: '/', icon: <HomeOutlined />, label: 'Home' },
  { key: '/fleetwood', icon: <HeartOutlined />, label: 'Health' },
  { key: '/queen', icon: <SafetyOutlined />, label: 'API & Entitlements' },
];

export function Layout() {
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  const selectedKey = menuItems.find((item) => {
    if (item.key === '/') return location.pathname === '/';
    return location.pathname.startsWith(item.key);
  })?.key || '/';

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        trigger={null}
        width={220}
        collapsedWidth={64}
        style={{ background: '#0f172a', borderRight: '1px solid #1e293b' }}
      >
        <div className={`flex items-center gap-2.5 px-5 py-4 border-b border-[#1e293b] ${collapsed ? 'justify-center px-0' : ''}`}>
          <img src="/logo-icon.svg" alt="Cavalier" className="w-[22px] h-[24px]" />
          {!collapsed && <span className="text-lg font-bold text-slate-50">Cavalier</span>}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100% - 57px)' }}>
          <Menu
            mode="inline"
            selectedKeys={[selectedKey]}
            items={menuItems}
            onClick={({ key }) => navigate(key)}
            className="!bg-transparent !border-none mt-2"
            style={{ flex: 1 }}
          />

          <div className="p-4 border-t border-[#1e293b]">
            {user && !collapsed && (
              <div className="mb-3">
                <div className="flex items-center gap-2 mb-1">
                  <Avatar size={24} className="!bg-[#006BFF] !text-xs">
                    {(user.name || user.email || 'U')[0].toUpperCase()}
                  </Avatar>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-slate-200 truncate">{user.name || user.email || user.sub || 'User'}</div>
                    {user.email && <div className="text-[11px] text-slate-500 truncate">{user.email}</div>}
                  </div>
                </div>
              </div>
            )}
            <div className={`flex flex-col gap-2 ${collapsed ? 'items-center' : ''}`}>
              <Button
                type="text"
                icon={<KeyOutlined />}
                onClick={() => setShowToken(true)}
                block={!collapsed}
                className="!text-sky-400"
              >
                {!collapsed && 'View Token'}
              </Button>
              <Button
                type="text"
                icon={<LogoutOutlined />}
                onClick={logout}
                block={!collapsed}
                className="!text-slate-400"
              >
                {!collapsed && 'Sign out'}
              </Button>
            </div>
          </div>

          <div
            className="border-t border-[#1e293b] cursor-pointer flex items-center justify-center text-slate-500 hover:text-slate-300"
            style={{ height: 40, flexShrink: 0 }}
            onClick={() => setCollapsed(!collapsed)}
          >
            {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
          </div>
        </div>
      </Sider>

      <AntLayout>
        <Content style={{ overflow: 'auto', background: '#121212' }}>
          <Outlet />
        </Content>
      </AntLayout>

      {showToken && <TokenModal onClose={() => setShowToken(false)} />}
    </AntLayout>
  );
}
