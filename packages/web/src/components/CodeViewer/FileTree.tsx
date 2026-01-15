import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, FileCode, Folder, FolderOpen } from 'lucide-react';
import type { Vulnerability, ArcVulnerability, Severity } from '../../types';

type VulnItem = Vulnerability | ArcVulnerability;

interface FileTreeProps {
  vulnerabilities: VulnItem[];
  selectedFile: string | null;
  onSelectFile: (filePath: string) => void;
}

interface FileNode {
  name: string;
  path: string;
  isDirectory: boolean;
  children: FileNode[];
  vulnCount: number;
  maxSeverity: Severity | null;
}

const SEVERITY_PRIORITY: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-green-500',
  info: 'text-gray-500',
};

function buildFileTree(vulnerabilities: VulnItem[]): FileNode[] {
  const root: Record<string, FileNode> = {};

  // Group vulnerabilities by file
  const vulnsByFile = new Map<string, VulnItem[]>();
  vulnerabilities.forEach((vuln) => {
    const existing = vulnsByFile.get(vuln.filePath) || [];
    existing.push(vuln);
    vulnsByFile.set(vuln.filePath, existing);
  });

  // Build tree structure
  vulnsByFile.forEach((vulns, filePath) => {
    const parts = filePath.split('/').filter(Boolean);
    let currentLevel = root;
    let currentPath = '';

    parts.forEach((part, index) => {
      currentPath = currentPath ? `${currentPath}/${part}` : part;
      const isLast = index === parts.length - 1;

      if (!currentLevel[part]) {
        const maxSeverity = isLast
          ? vulns.reduce((max, v) => {
              if (!max || SEVERITY_PRIORITY[v.severity] > SEVERITY_PRIORITY[max]) {
                return v.severity;
              }
              return max;
            }, null as Severity | null)
          : null;

        currentLevel[part] = {
          name: part,
          path: currentPath,
          isDirectory: !isLast,
          children: [],
          vulnCount: isLast ? vulns.length : 0,
          maxSeverity,
        };
      }

      if (!isLast) {
        // Convert children array to object for easier lookup
        const childrenObj: Record<string, FileNode> = {};
        currentLevel[part].children.forEach((child) => {
          childrenObj[child.name] = child;
        });
        currentLevel = childrenObj;
        // We'll rebuild children array later
      }
    });
  });

  // Convert to array and sort
  function toArray(obj: Record<string, FileNode>): FileNode[] {
    return Object.values(obj)
      .map((node) => ({
        ...node,
        children: node.isDirectory ? toArray(
          node.children.reduce((acc, child) => {
            acc[child.name] = child;
            return acc;
          }, {} as Record<string, FileNode>)
        ) : [],
      }))
      .sort((a, b) => {
        // Directories first, then alphabetically
        if (a.isDirectory && !b.isDirectory) return -1;
        if (!a.isDirectory && b.isDirectory) return 1;
        return a.name.localeCompare(b.name);
      });
  }

  // Simpler approach - rebuild from scratch
  const tree: FileNode[] = [];
  const nodeMap = new Map<string, FileNode>();

  vulnsByFile.forEach((vulns, filePath) => {
    const parts = filePath.split('/').filter(Boolean);
    let parentPath = '';

    parts.forEach((part, index) => {
      const currentPath = parentPath ? `${parentPath}/${part}` : part;
      const isFile = index === parts.length - 1;

      if (!nodeMap.has(currentPath)) {
        const maxSeverity = isFile
          ? vulns.reduce((max, v) => {
              if (!max || SEVERITY_PRIORITY[v.severity] > SEVERITY_PRIORITY[max]) {
                return v.severity;
              }
              return max;
            }, null as Severity | null)
          : null;

        const node: FileNode = {
          name: part,
          path: currentPath,
          isDirectory: !isFile,
          children: [],
          vulnCount: isFile ? vulns.length : 0,
          maxSeverity,
        };

        nodeMap.set(currentPath, node);

        if (parentPath) {
          const parent = nodeMap.get(parentPath);
          if (parent) {
            parent.children.push(node);
          }
        } else {
          tree.push(node);
        }
      }

      parentPath = currentPath;
    });
  });

  // Sort tree
  function sortTree(nodes: FileNode[]): FileNode[] {
    return nodes
      .map((node) => ({
        ...node,
        children: sortTree(node.children),
      }))
      .sort((a, b) => {
        if (a.isDirectory && !b.isDirectory) return -1;
        if (!a.isDirectory && b.isDirectory) return 1;
        return a.name.localeCompare(b.name);
      });
  }

  return sortTree(tree);
}

function TreeNode({
  node,
  selectedFile,
  onSelectFile,
  depth = 0,
}: {
  node: FileNode;
  selectedFile: string | null;
  onSelectFile: (path: string) => void;
  depth?: number;
}) {
  const [expanded, setExpanded] = useState(depth < 2);
  const isSelected = selectedFile === node.path;

  const handleClick = () => {
    if (node.isDirectory) {
      setExpanded(!expanded);
    } else {
      onSelectFile(node.path);
    }
  };

  return (
    <div>
      <button
        onClick={handleClick}
        className={`w-full flex items-center gap-1.5 px-2 py-1 text-left text-sm hover:bg-gray-700/50 rounded transition-colors ${
          isSelected ? 'bg-arc-purple/20 text-arc-purple' : 'text-gray-300'
        }`}
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
      >
        {/* Expand/collapse icon for directories */}
        {node.isDirectory ? (
          expanded ? (
            <ChevronDown className="w-4 h-4 text-gray-500 flex-shrink-0" />
          ) : (
            <ChevronRight className="w-4 h-4 text-gray-500 flex-shrink-0" />
          )
        ) : (
          <span className="w-4" />
        )}

        {/* File/folder icon */}
        {node.isDirectory ? (
          expanded ? (
            <FolderOpen className="w-4 h-4 text-yellow-500 flex-shrink-0" />
          ) : (
            <Folder className="w-4 h-4 text-yellow-500 flex-shrink-0" />
          )
        ) : (
          <FileCode className={`w-4 h-4 flex-shrink-0 ${
            node.maxSeverity ? SEVERITY_COLORS[node.maxSeverity] : 'text-gray-400'
          }`} />
        )}

        {/* Name */}
        <span className="truncate flex-1">{node.name}</span>

        {/* Vulnerability count badge */}
        {node.vulnCount > 0 && (
          <span className={`text-xs px-1.5 py-0.5 rounded ${
            node.maxSeverity ? `${SEVERITY_COLORS[node.maxSeverity]} bg-gray-700` : 'text-gray-500'
          }`}>
            {node.vulnCount}
          </span>
        )}
      </button>

      {/* Children */}
      {node.isDirectory && expanded && (
        <div>
          {node.children.map((child) => (
            <TreeNode
              key={child.path}
              node={child}
              selectedFile={selectedFile}
              onSelectFile={onSelectFile}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function FileTree({ vulnerabilities, selectedFile, onSelectFile }: FileTreeProps) {
  const tree = useMemo(() => buildFileTree(vulnerabilities), [vulnerabilities]);

  if (tree.length === 0) {
    return (
      <div className="p-4 text-gray-500 text-sm text-center">
        No files with vulnerabilities
      </div>
    );
  }

  return (
    <div className="py-2">
      {tree.map((node) => (
        <TreeNode
          key={node.path}
          node={node}
          selectedFile={selectedFile}
          onSelectFile={onSelectFile}
        />
      ))}
    </div>
  );
}
