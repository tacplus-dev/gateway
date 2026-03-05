import { useState, useEffect, useCallback, useMemo } from 'react';
import { Button, Input, Spin, Modal, Tabs } from 'antd';
import { create } from '@bufbuild/protobuf';
import { PolicyServiceRestClient } from '../../../../tacplus/wrappers/restclients/rest_clients';
import { EvaluatePolicyRequestSchema } from '../../../../tacplus/types/services/policy/policy_pb.ts';
import type { OpaPolicy } from '../../../../tacplus/libs/opa/opa_pb.ts';
import { fetchTransport } from '../../../auth/fetchTransport';
import { decodeBundleOrSource, encodeBundleToTgz } from './BundleUtils';
import type { BundleFile } from './BundleUtils';

const { TextArea } = Input;
const policyClient = new PolicyServiceRestClient(fetchTransport, '');

interface Props {
  entitlementsPolicy: OpaPolicy | null;
  claimMappingPolicy: OpaPolicy | null;
  loading: boolean;
}

// ---------------------------------------------------------------------------
// FileTree — recursive tree renderer
// ---------------------------------------------------------------------------

interface TreeNode {
  name: string;
  path: string;
  isDir: boolean;
  children: TreeNode[];
}

function buildTree(files: BundleFile[]): TreeNode[] {
  const root: TreeNode = { name: '', path: '', isDir: true, children: [] };

  for (const file of files) {
    const parts = file.path.split('/').filter(Boolean);
    let current = root;
    for (let i = 0; i < parts.length; i++) {
      const isLast = i === parts.length - 1;
      const partPath = parts.slice(0, i + 1).join('/');
      let child = current.children.find((c) => c.name === parts[i]);
      if (!child) {
        child = { name: parts[i], path: isLast ? file.path : partPath, isDir: !isLast, children: [] };
        current.children.push(child);
      }
      current = child;
    }
  }

  // Sort: dirs first, then alphabetical
  const sortNodes = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const n of nodes) if (n.isDir) sortNodes(n.children);
  };
  sortNodes(root.children);
  return root.children;
}

function FileTreeNode({
  node,
  selectedPath,
  onSelect,
  depth,
}: {
  node: TreeNode;
  selectedPath: string;
  onSelect: (path: string) => void;
  depth: number;
}) {
  const [expanded, setExpanded] = useState(true);
  const isSelected = node.path === selectedPath;

  if (node.isDir) {
    return (
      <div>
        <div
          className="flex items-center gap-1 py-0.5 px-1 cursor-pointer rounded hover:bg-[#334155] text-[13px] text-slate-400"
          style={{ paddingLeft: depth * 12 + 4 }}
          onClick={() => setExpanded(!expanded)}
        >
          <span className="w-4 text-center text-[11px]">{expanded ? '\u25BE' : '\u25B8'}</span>
          <span>{node.name}/</span>
        </div>
        {expanded && node.children.map((child) => (
          <FileTreeNode key={child.path} node={child} selectedPath={selectedPath} onSelect={onSelect} depth={depth + 1} />
        ))}
      </div>
    );
  }

  return (
    <div
      className={`flex items-center gap-1 py-0.5 px-1 cursor-pointer rounded text-[13px] ${
        isSelected ? 'bg-[#334155] text-white' : 'text-slate-300 hover:bg-[#1e293b]'
      }`}
      style={{ paddingLeft: depth * 12 + 4 }}
      onClick={() => onSelect(node.path)}
    >
      <span className="w-4 text-center text-[11px] text-slate-500">{'\u2022'}</span>
      <span className="font-mono">{node.name}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyBundle — single bundle editor (file tree + editor + actions)
// ---------------------------------------------------------------------------

function PolicyBundle({
  label,
  policy,
  serverPolicy,
}: {
  label: string;
  policy: OpaPolicy | null;
  serverPolicy: OpaPolicy | null;
}) {
  const [files, setFiles] = useState<BundleFile[]>([]);
  const [selectedPath, setSelectedPath] = useState('');
  const [decoding, setDecoding] = useState(true);

  // Test policy state
  const [testInput, setTestInput] = useState('{}');
  const [testQuery, setTestQuery] = useState('');
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);

  // New file state
  const [showNewFile, setShowNewFile] = useState(false);
  const [newFileName, setNewFileName] = useState('');

  // Decode policy on mount/change
  useEffect(() => {
    if (!policy) {
      setFiles([]);
      setDecoding(false);
      return;
    }
    setDecoding(true);
    decodeBundleOrSource(policy).then((decoded) => {
      setFiles(decoded);
      if (decoded.length > 0 && !decoded.find((f) => f.path === selectedPath)) {
        setSelectedPath(decoded[0].path);
      }
      setDecoding(false);
    });
  }, [policy]); // eslint-disable-line react-hooks/exhaustive-deps

  const tree = useMemo(() => buildTree(files), [files]);
  const selectedFile = files.find((f) => f.path === selectedPath);

  const updateFileContent = useCallback(
    (content: string) => {
      setFiles((prev) => prev.map((f) => (f.path === selectedPath ? { ...f, content } : f)));
    },
    [selectedPath],
  );

  const handleAddFile = useCallback(() => {
    if (!newFileName.trim()) return;
    const path = newFileName.trim();
    if (files.find((f) => f.path === path)) return;
    setFiles((prev) => [...prev, { path, content: 'package authz\n' }]);
    setSelectedPath(path);
    setShowNewFile(false);
    setNewFileName('');
  }, [newFileName, files]);

  const handleDeleteFile = useCallback(() => {
    if (!selectedPath) return;
    setFiles((prev) => {
      const next = prev.filter((f) => f.path !== selectedPath);
      if (next.length > 0) setSelectedPath(next[0].path);
      else setSelectedPath('');
      return next;
    });
  }, [selectedPath]);

  const handleReset = useCallback(() => {
    if (!serverPolicy) return;
    decodeBundleOrSource(serverPolicy).then((decoded) => {
      setFiles(decoded);
      if (decoded.length > 0) setSelectedPath(decoded[0].path);
    });
  }, [serverPolicy]);

  const handleDownload = useCallback(async () => {
    const blob = await encodeBundleToTgz(files);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${label.toLowerCase().replace(/\s+/g, '-')}-bundle.tar.gz`;
    a.click();
    URL.revokeObjectURL(url);
  }, [files, label]);

  const handleTest = useCallback(async () => {
    if (!selectedFile) return;
    setTesting(true);
    setTestResult(null);
    setTestError(null);
    try {
      const resp = await policyClient.evaluatePolicy(
        create(EvaluatePolicyRequestSchema, {
          regoSource: selectedFile.content,
          inputJson: testInput,
          query: testQuery || undefined,
        }),
      );
      if (resp.errors.length > 0) {
        setTestError(resp.errors.join('\n'));
      } else {
        setTestResult(
          `${resp.allowed ? 'ALLOWED' : 'DENIED'}\n\n${JSON.stringify(JSON.parse(resp.resultJson), null, 2)}`,
        );
      }
    } catch (err) {
      setTestError(err instanceof Error ? err.message : 'Evaluation failed');
    } finally {
      setTesting(false);
    }
  }, [selectedFile, testInput, testQuery]);

  if (decoding) {
    return <div className="py-4 text-center"><Spin size="small" /></div>;
  }

  if (files.length === 0) {
    return <div className="py-4 text-center text-slate-500 text-[13px]">No policy configured.</div>;
  }

  return (
    <div>
      {/* Toolbar */}
      <div className="flex items-center gap-2 mb-3">
        <Button size="small" onClick={() => setShowNewFile(true)}>New File</Button>
        <Button size="small" danger onClick={handleDeleteFile} disabled={!selectedPath}>Delete</Button>
        <Button size="small" onClick={handleDownload}>Download .tgz</Button>
        <Button size="small" onClick={() => setShowTestModal(true)} disabled={!selectedFile}>Test Policy</Button>
        <Button size="small" onClick={handleReset}>Reset to deployed</Button>

        {/* Inline new-file input */}
        {showNewFile && (
          <div className="flex items-center gap-1 ml-2">
            <Input
              size="small"
              placeholder="path/to/file.rego"
              value={newFileName}
              onChange={(e) => setNewFileName(e.target.value)}
              onPressEnter={handleAddFile}
              className="!w-48 !bg-[#0f172a] !border-[#334155] !text-slate-200 font-mono text-[12px]"
              autoFocus
            />
            <Button size="small" type="primary" onClick={handleAddFile}>Add</Button>
            <Button size="small" onClick={() => { setShowNewFile(false); setNewFileName(''); }}>Cancel</Button>
          </div>
        )}
      </div>

      {/* Two-column layout */}
      <div className="flex gap-0 border border-[#334155] rounded-lg overflow-hidden" style={{ minHeight: 400 }}>
        {/* File tree (left) */}
        <div className="w-[30%] min-w-[180px] border-r border-[#334155] bg-[#0c1322] py-2 overflow-auto">
          {tree.map((node) => (
            <FileTreeNode key={node.path} node={node} selectedPath={selectedPath} onSelect={setSelectedPath} depth={0} />
          ))}
        </div>

        {/* Editor (right) */}
        <div className="flex-1 flex flex-col bg-[#0f172a]">
          {selectedFile ? (
            <>
              <div className="px-3 py-1.5 border-b border-[#334155] text-[12px] text-slate-500 font-mono">
                {selectedFile.path}
              </div>
              <textarea
                value={selectedFile.content}
                onChange={(e) => updateFileContent(e.target.value)}
                spellCheck={false}
                className="flex-1 w-full resize-none bg-transparent text-slate-200 font-mono text-[13px] p-3 outline-none border-none leading-relaxed"
              />
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-[13px]">
              Select a file to edit
            </div>
          )}
        </div>
      </div>

      {/* Test Policy Modal */}
      <Modal
        title="Test Policy"
        open={showTestModal}
        onCancel={() => setShowTestModal(false)}
        footer={null}
        width={640}
      >
        <div className="mb-3">
          <label className="block text-[13px] font-semibold text-slate-400 mb-1">Input JSON</label>
          <TextArea
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            spellCheck={false}
            autoSize={{ minRows: 4, maxRows: 12 }}
            className="!bg-[#0f172a] !border-[#334155] !text-slate-200 font-mono text-[13px]"
          />
        </div>
        <div className="mb-3">
          <label className="block text-[13px] font-semibold text-slate-400 mb-1">
            Query <span className="font-normal text-slate-600">(default: data.authz.allow)</span>
          </label>
          <Input
            value={testQuery}
            onChange={(e) => setTestQuery(e.target.value)}
            placeholder="data.authz.allow"
            className="!bg-[#0f172a] !border-[#334155] !text-slate-200 font-mono text-[13px]"
          />
        </div>
        <Button type="primary" onClick={handleTest} loading={testing} className="mb-3">
          Evaluate
        </Button>
        {testError && (
          <pre className="mt-2 p-3 rounded bg-red-950 border border-red-800 text-red-300 text-[12px] font-mono whitespace-pre-wrap">
            {testError}
          </pre>
        )}
        {testResult && (
          <pre className="mt-2 p-3 rounded bg-[#0f172a] border border-[#334155] text-slate-200 text-[12px] font-mono whitespace-pre-wrap">
            {testResult}
          </pre>
        )}
      </Modal>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyEditor — tabs for entitlements + claim mapping
// ---------------------------------------------------------------------------

export function PolicyEditor({ entitlementsPolicy, claimMappingPolicy, loading }: Props) {
  if (loading) {
    return <div className="text-center py-6"><Spin tip="Loading policies..." /></div>;
  }

  return (
    <div>
      <div className="mb-3">
        <span className="text-base font-bold text-slate-200">OPA Policy Bundles</span>
        <p className="text-[13px] text-slate-500 mt-1 mb-0">
          Browse and edit policy files. Changes are local only — download as .tgz to deploy.
        </p>
      </div>

      <Tabs
        defaultActiveKey="entitlements"
        items={[
          {
            key: 'entitlements',
            label: 'Entitlements Policy',
            children: (
              <PolicyBundle
                label="Entitlements"
                policy={entitlementsPolicy}
                serverPolicy={entitlementsPolicy}
              />
            ),
          },
          {
            key: 'claim-mapping',
            label: 'Claim Mapping Policy',
            children: (
              <PolicyBundle
                label="Claim Mapping"
                policy={claimMappingPolicy}
                serverPolicy={claimMappingPolicy}
              />
            ),
          },
        ]}
      />
    </div>
  );
}
