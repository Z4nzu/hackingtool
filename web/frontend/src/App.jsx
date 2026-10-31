import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  FolderOpen,
  Globe,
  LayoutDashboard,
  Network,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Terminal,
  Target,
  Wrench,
  X,
} from 'lucide-react'

const API_BASE = 'http://localhost:8000'

const visibilityModes = [
  { id: 'active', label: 'Active' },
  { id: 'installed', label: 'Installed' },
  { id: 'archived', label: 'Archived' },
  { id: 'incompatible', label: 'Unsupported' },
  { id: 'all', label: 'All' },
]

const requirementLabels = {
  root: 'Root',
  wifi: 'Wi-Fi',
  go: 'Go',
  ruby: 'Ruby',
  java: 'Java',
  docker: 'Docker',
}

function CategoryGlyph({ index }) {
  if (index % 4 === 0) return <Globe className="w-5 h-5" />
  if (index % 3 === 0) return <Terminal className="w-5 h-5" />
  if (index % 2 === 0) return <Shield className="w-5 h-5" />
  return <Settings className="w-5 h-5" />
}

function App() {
  const [systemInfo, setSystemInfo] = useState(null)
  const [categories, setCategories] = useState([])
  const [tools, setTools] = useState([])
  const [activeTab, setActiveTab] = useState('dashboard')
  const [targetScope, setTargetScope] = useState('*.example.com')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategoryId, setSelectedCategoryId] = useState(null)
  const [visibilityFilter, setVisibilityFilter] = useState('active')
  const [selectedToolId, setSelectedToolId] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [actionState, setActionState] = useState({
    loading: false,
    title: '',
    output: '',
    error: '',
  })

  const loadCatalog = async (toolToReselect = null) => {
    setIsLoading(true)
    setLoadError('')
    try {
      const [systemRes, categoriesRes, toolsRes] = await Promise.all([
        fetch(`${API_BASE}/api/system`),
        fetch(`${API_BASE}/api/categories`),
        fetch(`${API_BASE}/api/tools`),
      ])

      if (!systemRes.ok || !categoriesRes.ok || !toolsRes.ok) {
        throw new Error('Failed to load backend catalog.')
      }

      const [systemData, categoriesData, toolsData] = await Promise.all([
        systemRes.json(),
        categoriesRes.json(),
        toolsRes.json(),
      ])

      setSystemInfo(systemData)
      setCategories(categoriesData)
      setTools(toolsData)

      if (toolToReselect) {
        const refreshedTool = toolsData.find((tool) => tool.id === toolToReselect)
        setSelectedToolId(refreshedTool ? refreshedTool.id : null)
      }
    } catch (error) {
      setLoadError(error.message || 'Failed to load frontend data.')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadCatalog()
  }, [])

  const selectedCategory = categories.find((category) => category.id === selectedCategoryId) || null
  const selectedTool = tools.find((tool) => tool.id === selectedToolId) || null

  const openRegistry = ({ categoryId = null, visibility = 'active' } = {}) => {
    setSelectedCategoryId(categoryId)
    setVisibilityFilter(visibility)
    setActiveTab('tools')
  }

  const clearFilters = () => {
    setSelectedCategoryId(null)
    setVisibilityFilter('active')
    setSearchQuery('')
  }

  const filteredTools = tools.filter((tool) => {
    const matchesSearch =
      tool.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.topLevelCategory.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.tags.some((tag) => tag.toLowerCase().includes(searchQuery.toLowerCase()))

    const matchesCategory = !selectedCategoryId || tool.categoryId === selectedCategoryId

    let matchesVisibility = true
    if (visibilityFilter === 'active') {
      matchesVisibility = !tool.archived && tool.compatible
    } else if (visibilityFilter === 'installed') {
      matchesVisibility = tool.installed
    } else if (visibilityFilter === 'archived') {
      matchesVisibility = tool.archived
    } else if (visibilityFilter === 'incompatible') {
      matchesVisibility = !tool.archived && !tool.compatible
    }

    return matchesSearch && matchesCategory && matchesVisibility
  })

  const installedToolsCount = tools.filter((tool) => tool.installed).length
  const archivedToolsCount = tools.filter((tool) => tool.archived).length
  const incompatibleToolsCount = tools.filter((tool) => !tool.archived && !tool.compatible).length

  const selectedCategorySupportsInstallAll =
    selectedCategory && selectedCategory.supportsInstallAll && visibilityFilter !== 'archived'

  const executeAction = async ({ url, title, toolIdToReselect = selectedToolId }) => {
    setActionState({
      loading: true,
      title,
      output: '',
      error: '',
    })

    try {
      const response = await fetch(url, { method: 'POST' })
      const payload = await response.json()
      const combinedOutput = [payload.stdout, payload.stderr].filter(Boolean).join('\n')

      if (!response.ok || payload.success === false) {
        setActionState({
          loading: false,
          title,
          output: combinedOutput,
          error: payload.detail || 'Action failed.',
        })
      } else {
        setActionState({
          loading: false,
          title,
          output: combinedOutput || 'Action completed without console output.',
          error: '',
        })
      }

      await loadCatalog(toolIdToReselect)
    } catch (error) {
      setActionState({
        loading: false,
        title,
        output: '',
        error: error.message || 'Action failed.',
      })
    }
  }

  const runToolAction = (tool, actionName, label) =>
    executeAction({
      url: `${API_BASE}/api/tools/${tool.id}/actions/${actionName}`,
      title: `${label} · ${tool.title}`,
      toolIdToReselect: tool.id,
    })

  const runToolOption = (tool, option) =>
    executeAction({
      url: `${API_BASE}/api/tools/${tool.id}/options/${option.index}`,
      title: `${option.label} · ${tool.title}`,
      toolIdToReselect: tool.id,
    })

  const installMissingForCategory = (category) =>
    executeAction({
      url: `${API_BASE}/api/categories/${category.id}/actions/install-missing`,
      title: `Install Missing · ${category.label}`,
      toolIdToReselect: selectedToolId,
    })

  const openProjectPage = (tool) => {
    if (tool.projectUrl) {
      window.open(tool.projectUrl, '_blank', 'noopener,noreferrer')
    }
  }

  const copyLocalPath = async (tool) => {
    if (!tool.localPath || !navigator.clipboard) return
    await navigator.clipboard.writeText(tool.localPath)
    setActionState({
      loading: false,
      title: `Path copied · ${tool.title}`,
      output: tool.localPath,
      error: '',
    })
  }

  const renderActionOutput = () => {
    if (!actionState.title && !actionState.loading && !actionState.error && !actionState.output) return null

    return (
      <div className="card">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-xs font-mono uppercase tracking-[0.2em] text-muted">Action Console</div>
            <div className="text-sm font-medium mt-2">{actionState.title || 'Latest action'}</div>
          </div>
          {actionState.loading && <RefreshCw className="w-4 h-4 animate-spin text-primary" />}
        </div>
        {actionState.error && (
          <div className="mt-4 border border-divider rounded-md p-3 text-sm text-red-300 bg-[#160909]">
            {actionState.error}
          </div>
        )}
        <pre className="mt-4 bg-background border border-divider rounded-md p-4 text-xs text-muted overflow-x-auto whitespace-pre-wrap">
          {actionState.output || (actionState.loading ? 'Working...' : 'No output yet.')}
        </pre>
      </div>
    )
  }

  const renderToolActionButtons = (tool) => {
    const supportedOptions = tool.options.filter((option) => option.webSupported)

    return (
      <div className="flex flex-wrap gap-2">
        {supportedOptions.map((option) => {
          if (option.kind === 'install') {
            return (
              <button
                key={`${tool.id}-${option.index}`}
                type="button"
                onClick={() => runToolAction(tool, 'install', option.label)}
                className="btn-primary text-xs uppercase tracking-wider font-mono"
                disabled={actionState.loading}
              >
                Install
              </button>
            )
          }

          if (option.kind === 'update') {
            return (
              <button
                key={`${tool.id}-${option.index}`}
                type="button"
                onClick={() => runToolAction(tool, 'update', option.label)}
                className="btn-secondary text-xs uppercase tracking-wider font-mono"
                disabled={actionState.loading}
              >
                Update
              </button>
            )
          }

          if (option.kind === 'uninstall') {
            return (
              <button
                key={`${tool.id}-${option.index}`}
                type="button"
                onClick={() => runToolAction(tool, 'uninstall', option.label)}
                className="btn-secondary text-xs uppercase tracking-wider font-mono"
                disabled={actionState.loading}
              >
                Uninstall
              </button>
            )
          }

          if (option.kind === 'run') {
            return (
              <button
                key={`${tool.id}-${option.index}`}
                type="button"
                onClick={() => runToolAction(tool, 'run', option.label)}
                className="btn-secondary text-xs uppercase tracking-wider font-mono"
                disabled={actionState.loading}
              >
                Run
              </button>
            )
          }

          return (
            <button
              key={`${tool.id}-${option.index}`}
              type="button"
              onClick={() => runToolOption(tool, option)}
              className="btn-secondary text-xs uppercase tracking-wider font-mono"
              disabled={actionState.loading}
            >
              {option.label}
            </button>
          )
        })}

        {tool.projectUrl && (
          <button
            type="button"
            onClick={() => openProjectPage(tool)}
            className="btn-secondary text-xs uppercase tracking-wider font-mono"
          >
            <ExternalLink className="w-3 h-3" />
            Project
          </button>
        )}

        {tool.localPath && (
          <button
            type="button"
            onClick={() => copyLocalPath(tool)}
            className="btn-secondary text-xs uppercase tracking-wider font-mono"
          >
            <FolderOpen className="w-3 h-3" />
            Path
          </button>
        )}
      </div>
    )
  }

  const renderToolDetailModal = () => {
    if (!selectedTool) return null

    const requirementBadges = Object.entries(selectedTool.requires).filter(([, enabled]) => enabled)
    const unsupportedOptions = selectedTool.options.filter((option) => !option.webSupported)

    return (
      <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm p-4 md:p-8 overflow-y-auto">
        <div className="max-w-5xl mx-auto">
          <div className="card p-0 overflow-hidden">
            <div className="border-b border-divider p-6 flex items-start justify-between gap-4">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-[0.25em] text-muted">
                  {selectedTool.categoryLabel} · {selectedTool.category}
                </div>
                <h2 className="text-2xl font-display uppercase tracking-wider mt-3">{selectedTool.title}</h2>
                <p className="text-sm text-muted mt-3 max-w-3xl leading-relaxed">
                  {selectedTool.description || 'No detailed description is defined for this tool yet.'}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedToolId(null)}
                className="btn-secondary px-3 py-2"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Status</div>
                  <div className="mt-3 text-sm">
                    {selectedTool.installed ? 'Installed' : 'Not installed'}
                  </div>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Compatibility</div>
                  <div className="mt-3 text-sm">
                    {selectedTool.compatible ? 'Supported here' : selectedTool.supportReason}
                  </div>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Top Level</div>
                  <div className="mt-3 text-sm">{selectedTool.topLevelCategory}</div>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Supported OS</div>
                  <div className="mt-3 text-sm">{selectedTool.supportedOs.join(', ')}</div>
                </div>
              </div>

              {(selectedTool.archived || selectedTool.archivedReason) && (
                <div className="border border-divider rounded-lg p-4 bg-[#15120c]">
                  <div className="flex items-center gap-2 text-sm uppercase tracking-[0.2em] text-yellow-300 font-mono">
                    <AlertTriangle className="w-4 h-4" />
                    Archived Tool
                  </div>
                  <p className="text-sm text-yellow-100/80 mt-3">
                    {selectedTool.archivedReason || 'This tool is archived and may be unmaintained.'}
                  </p>
                </div>
              )}

              <div>
                <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted mb-3">Web Actions</div>
                {renderToolActionButtons(selectedTool)}
              </div>

              {requirementBadges.length > 0 && (
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted mb-3">Requirements</div>
                  <div className="flex flex-wrap gap-2">
                    {requirementBadges.map(([key]) => (
                      <span key={key} className="badge">
                        {requirementLabels[key]}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedTool.tags.length > 0 && (
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted mb-3">Tags</div>
                  <div className="flex flex-wrap gap-2">
                    {selectedTool.tags.map((tag) => (
                      <span key={tag} className="badge">{tag}</span>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Install Commands</div>
                  <pre className="mt-4 text-xs text-muted whitespace-pre-wrap overflow-x-auto">
                    {selectedTool.commands.install.length > 0 ? selectedTool.commands.install.join('\n') : 'No install commands defined.'}
                  </pre>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Run Commands</div>
                  <pre className="mt-4 text-xs text-muted whitespace-pre-wrap overflow-x-auto">
                    {selectedTool.commands.run.length > 0 ? selectedTool.commands.run.join('\n') : 'No direct run commands defined.'}
                  </pre>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Uninstall Commands</div>
                  <pre className="mt-4 text-xs text-muted whitespace-pre-wrap overflow-x-auto">
                    {selectedTool.commands.uninstall.length > 0 ? selectedTool.commands.uninstall.join('\n') : 'No uninstall commands defined.'}
                  </pre>
                </div>
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Local Path</div>
                  <div className="mt-4 text-sm break-all">{selectedTool.localPath || 'Tool path not detected yet.'}</div>
                </div>
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">Project URL</div>
                  <div className="mt-4 text-sm break-all">{selectedTool.projectUrl || 'No project URL supplied.'}</div>
                </div>
              </div>

              {unsupportedOptions.length > 0 && (
                <div className="card p-4">
                  <div className="text-[11px] font-mono uppercase tracking-[0.2em] text-muted">CLI-Only Actions</div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {unsupportedOptions.map((option) => (
                      <span key={`${selectedTool.id}-${option.index}`} className="badge">
                        {option.label}
                      </span>
                    ))}
                  </div>
                  <p className="text-sm text-muted mt-4">
                    These actions are exposed from the CLI but still need a better web execution flow because they open shells,
                    prompt for input, or launch external apps.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background text-text flex flex-col font-sans">
      <header className="border-b border-divider bg-background sticky top-0 z-40">
        <div className="max-w-[1500px] mx-auto px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 border border-divider flex items-center justify-center rounded">
              <Shield className="w-6 h-6 text-primary" strokeWidth={1.5} />
            </div>
            <div className="flex flex-col">
              <span className="font-display font-bold text-lg tracking-tight uppercase leading-none">Hacking Tool</span>
              <span className="text-[10px] text-muted font-mono tracking-widest uppercase mt-1">Frontend Control Plane</span>
            </div>
          </div>

          <nav className="flex items-center space-x-1 border border-divider p-1 rounded">
            <button
              type="button"
              onClick={() => setActiveTab('dashboard')}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-all flex items-center gap-2 ${activeTab === 'dashboard' ? 'bg-primary text-black' : 'text-muted hover:text-primary hover:bg-surfaceHover'}`}
            >
              <LayoutDashboard className="w-4 h-4" />
              Overview
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('tools')}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-all flex items-center gap-2 ${activeTab === 'tools' ? 'bg-primary text-black' : 'text-muted hover:text-primary hover:bg-surfaceHover'}`}
            >
              <Terminal className="w-4 h-4" />
              Registry
            </button>
          </nav>
        </div>
      </header>

      <main className="flex-1 max-w-[1500px] w-full mx-auto px-6 py-8 space-y-8">
        <div className="grid grid-cols-1 xl:grid-cols-[1.4fr_1fr] gap-4">
          <div className="card p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3 w-full sm:w-auto">
              <Target className="w-5 h-5 text-muted" />
              <div className="flex flex-col flex-1 sm:w-72">
                <label className="text-[10px] uppercase font-mono text-muted mb-1">Authorized Target Scope</label>
                <input
                  type="text"
                  value={targetScope}
                  onChange={(event) => setTargetScope(event.target.value)}
                  className="bg-transparent border-b border-dividerHover focus:border-primary outline-none text-sm font-mono pb-1 transition-colors"
                  placeholder="IP, Domain, or CIDR"
                />
              </div>
            </div>
            <div className="flex items-center gap-3 border border-divider px-3 py-1.5 rounded bg-background">
              <div className="w-2 h-2 rounded-full bg-success animate-pulse"></div>
              <span className="text-xs font-mono text-muted uppercase">System Armed</span>
            </div>
          </div>

          <div className="card p-4 flex flex-col justify-between gap-4">
            <div>
              <div className="text-[10px] uppercase font-mono text-muted">Execution Context</div>
              <div className="mt-3 text-sm">
                {systemInfo ? `${systemInfo.os.system} · ${systemInfo.os.packageManager || 'manual pkg manager'}` : 'Loading system profile...'}
              </div>
            </div>
            <div className="text-xs font-mono text-muted break-all">
              {systemInfo ? systemInfo.paths.toolsDir : 'Fetching tools directory...'}
            </div>
          </div>
        </div>

        {loadError && (
          <div className="border border-divider rounded-lg p-4 bg-[#160909] text-red-200">
            {loadError}
          </div>
        )}

        {renderActionOutput()}

        {activeTab === 'dashboard' && (
          <div className="space-y-8 animate-in fade-in duration-500">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
              <button type="button" onClick={() => openRegistry({ visibility: 'all' })} className="card text-left group cursor-pointer">
                <div className="flex items-center justify-between mb-2 text-muted">
                  <span className="text-xs uppercase tracking-wider font-mono">Modules</span>
                  <Terminal className="w-4 h-4 group-hover:text-primary transition-colors" />
                </div>
                <div className="text-3xl font-display">{tools.length || '--'}</div>
                <div className="mt-3 text-[11px] uppercase tracking-[0.2em] text-muted">Full inventory</div>
              </button>

              <button type="button" onClick={() => openRegistry({ visibility: 'all' })} className="card text-left group cursor-pointer">
                <div className="flex items-center justify-between mb-2 text-muted">
                  <span className="text-xs uppercase tracking-wider font-mono">Categories</span>
                  <LayoutDashboard className="w-4 h-4 group-hover:text-primary transition-colors" />
                </div>
                <div className="text-3xl font-display">{categories.length || '--'}</div>
                <div className="mt-3 text-[11px] uppercase tracking-[0.2em] text-muted">Top-level vectors</div>
              </button>

              <button type="button" onClick={() => openRegistry({ visibility: 'installed' })} className="card text-left group cursor-pointer">
                <div className="flex items-center justify-between mb-2 text-muted">
                  <span className="text-xs uppercase tracking-wider font-mono">Installed</span>
                  <Download className="w-4 h-4 group-hover:text-primary transition-colors" />
                </div>
                <div className="text-3xl font-display">{installedToolsCount}</div>
                <div className="mt-3 text-[11px] uppercase tracking-[0.2em] text-muted">Ready now</div>
              </button>

              <button type="button" onClick={() => openRegistry({ visibility: 'archived' })} className="card text-left group cursor-pointer">
                <div className="flex items-center justify-between mb-2 text-muted">
                  <span className="text-xs uppercase tracking-wider font-mono">Archived</span>
                  <AlertTriangle className="w-4 h-4 group-hover:text-primary transition-colors" />
                </div>
                <div className="text-3xl font-display">{archivedToolsCount}</div>
                <div className="mt-3 text-[11px] uppercase tracking-[0.2em] text-muted">Legacy modules</div>
              </button>

              <button type="button" onClick={() => openRegistry({ visibility: 'incompatible' })} className="card text-left group cursor-pointer">
                <div className="flex items-center justify-between mb-2 text-muted">
                  <span className="text-xs uppercase tracking-wider font-mono">Unsupported</span>
                  <Wrench className="w-4 h-4 group-hover:text-primary transition-colors" />
                </div>
                <div className="text-3xl font-display">{incompatibleToolsCount}</div>
                <div className="mt-3 text-[11px] uppercase tracking-[0.2em] text-muted">Hidden in CLI</div>
              </button>
            </div>

            <div>
              <h2 className="text-sm font-mono uppercase tracking-widest text-muted mb-4 flex items-center gap-2">
                <Network className="w-4 h-4" /> Tactical Vectors
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {categories.map((category, index) => (
                  <button
                    key={category.id}
                    type="button"
                    onClick={() => openRegistry({ categoryId: category.id, visibility: 'active' })}
                    className="card text-left group cursor-pointer"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="text-muted group-hover:text-primary transition-colors">
                        <CategoryGlyph index={index} />
                      </div>
                      <div className="text-right text-[10px] font-mono uppercase tracking-[0.2em] text-muted">
                        {category.counts.installed}/{category.counts.total} installed
                      </div>
                    </div>
                    <div className="mt-5 text-base font-display uppercase tracking-wide">{category.label}</div>
                    <div className="mt-2 text-sm text-muted leading-relaxed">
                      {category.description || category.title}
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2 text-[10px] font-mono uppercase tracking-[0.2em] text-muted">
                      <span>{category.counts.active} active</span>
                      <span>{category.counts.archived} archived</span>
                      <span>{category.counts.incompatible} unsupported</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'tools' && (
          <div className="space-y-6 animate-in fade-in duration-500">
            <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
              <div>
                <h2 className="text-xl font-display uppercase tracking-wider">Module Registry</h2>
                <p className="text-xs font-mono uppercase tracking-[0.2em] text-muted mt-2">
                  {selectedCategory ? `${selectedCategory.label} · ` : ''}
                  {visibilityModes.find((mode) => mode.id === visibilityFilter)?.label} · {filteredTools.length} visible
                </p>
              </div>

              <div className="flex flex-col sm:flex-row gap-3 w-full lg:w-auto">
                <div className="relative w-full sm:w-80">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                  <input
                    type="text"
                    placeholder="Search tools, tags, or categories..."
                    value={searchQuery}
                    onChange={(event) => setSearchQuery(event.target.value)}
                    className="w-full bg-surface border border-divider rounded-md pl-9 pr-4 py-2 text-sm focus:border-primary outline-none transition-colors"
                  />
                </div>

                {selectedCategorySupportsInstallAll && (
                  <button
                    type="button"
                    onClick={() => installMissingForCategory(selectedCategory)}
                    className="btn-primary text-xs uppercase tracking-wider font-mono"
                    disabled={actionState.loading}
                  >
                    <Download className="w-3 h-3" />
                    Install Missing
                  </button>
                )}
              </div>
            </div>

            <div className="card p-4 space-y-4">
              <div className="flex flex-wrap gap-2">
                {visibilityModes.map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setVisibilityFilter(mode.id)}
                    className={`btn-secondary px-3 py-1.5 text-xs uppercase tracking-wider font-mono ${visibilityFilter === mode.id ? 'border-primary text-primary' : ''}`}
                  >
                    {mode.label}
                  </button>
                ))}

                {(selectedCategoryId || searchQuery || visibilityFilter !== 'active') && (
                  <button type="button" onClick={clearFilters} className="btn-secondary px-3 py-1.5 text-xs uppercase tracking-wider font-mono">
                    <X className="w-3 h-3" />
                    Reset
                  </button>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedCategoryId(null)}
                  className={`btn-secondary px-3 py-1.5 text-xs uppercase tracking-wider font-mono ${selectedCategoryId === null ? 'border-primary text-primary' : ''}`}
                >
                  All Categories
                </button>
                {categories.map((category) => (
                  <button
                    key={category.id}
                    type="button"
                    onClick={() => setSelectedCategoryId(category.id)}
                    className={`btn-secondary px-3 py-1.5 text-xs uppercase tracking-wider font-mono ${selectedCategoryId === category.id ? 'border-primary text-primary' : ''}`}
                  >
                    {category.label}
                  </button>
                ))}
              </div>
            </div>

            {isLoading ? (
              <div className="card py-10 text-center text-sm text-muted">Refreshing registry...</div>
            ) : filteredTools.length === 0 ? (
              <div className="card py-10 text-center">
                <div className="text-lg font-display uppercase tracking-wider">No tools match this filter</div>
                <p className="text-sm text-muted mt-3">Try another visibility mode, clear the search, or switch categories.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {filteredTools.map((tool) => (
                  <div key={tool.id} className="card flex flex-col p-5">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap gap-2 mb-3">
                          <span className="badge">{tool.categoryLabel}</span>
                          {tool.category !== tool.topLevelCategory && <span className="badge">{tool.category}</span>}
                          {tool.installed && <span className="badge">Installed</span>}
                          {tool.archived && <span className="badge">Archived</span>}
                          {!tool.archived && !tool.compatible && <span className="badge">Unsupported</span>}
                        </div>
                        <h3 className="font-bold text-base font-display uppercase tracking-wide">{tool.title}</h3>
                      </div>
                      <div className={`${tool.installed ? 'text-primary' : 'text-muted'}`}>
                        {tool.installed ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                      </div>
                    </div>

                    <p className="text-sm text-muted mt-4 leading-relaxed flex-grow">
                      {tool.description || 'No description available for this module.'}
                    </p>

                    {tool.tags.length > 0 && (
                      <div className="mt-4 flex flex-wrap gap-2">
                        {tool.tags.slice(0, 4).map((tag) => (
                          <span key={tag} className="badge">{tag}</span>
                        ))}
                      </div>
                    )}

                    {!tool.compatible && (
                      <div className="mt-4 text-xs text-yellow-200/80 border border-divider rounded-md p-3 bg-[#15120c]">
                        {tool.supportReason}
                      </div>
                    )}

                    <div className="mt-5 flex flex-wrap gap-2">
                      {tool.actions.canInstall && !tool.installed && (
                        <button
                          type="button"
                          onClick={() => runToolAction(tool, 'install', 'Install')}
                          className="btn-primary text-xs uppercase tracking-wider font-mono"
                          disabled={actionState.loading}
                        >
                          Install
                        </button>
                      )}
                      {tool.actions.canUpdate && tool.installed && (
                        <button
                          type="button"
                          onClick={() => runToolAction(tool, 'update', 'Update')}
                          className="btn-secondary text-xs uppercase tracking-wider font-mono"
                          disabled={actionState.loading}
                        >
                          Update
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => setSelectedToolId(tool.id)}
                        className="btn-secondary text-xs uppercase tracking-wider font-mono"
                      >
                        Details
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      {renderToolDetailModal()}

      <footer className="py-6 border-t border-divider text-center text-xs font-mono text-muted">
        support: <a href="https://github.com/imranshiundu/open-defense-kit" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">ODK</a>
      </footer>
    </div>
  )
}

export default App
