import { useCallback, useEffect, useMemo, useState } from 'react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { DragDropContext, Draggable, Droppable, type DropResult } from '@hello-pangea/dnd'
import './App.css'

type User = { id: number; email: string; nickname?: string; is_admin: boolean; github_id?: string; google_id?: string }
type Category = { id: number; name: string; description?: string; sort_order: number }
type LinkItem = { id: number; category_id: number; title: string; url: string; is_public: boolean; sort_order: number; icon_url?: string; click_count?: number; remark?: string }

const API_BASE = import.meta.env.VITE_API_BASE || ''

function Modal({ isOpen, onClose, title, children }: { isOpen: boolean; onClose: () => void; title: string; children: React.ReactNode }) {
  if (!isOpen) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-xl font-bold text-gray-800">{title}</h3>
          <button onClick={onClose} className="rounded-full p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600">
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const full = (() => {
    if (API_BASE) return `${API_BASE}${path}`
    if (path.startsWith('/api')) return path
    return `/api${path}`
  })()
  const res = await fetch(full, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    credentials: 'include',
  })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(text || res.statusText)
  }
  if (!text) return {} as T
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('响应不是有效的 JSON，请检查后端是否启动或代理配置')
  }
}

type AppConfig = { allow_register: boolean }

function getErrorMessage(error: unknown, fallback: string) {
  if (!(error instanceof Error) || !error.message) return fallback

  const raw = error.message.trim()
  try {
    const parsed = JSON.parse(raw) as { error?: string; message?: string }
    const serverMessage = (parsed.error || parsed.message || '').trim()
    if (!serverMessage) return fallback

    switch (serverMessage) {
      case 'invalid credentials':
        return '邮箱、密码或 OTP 不正确'
      case 'email and password required':
        return '请输入邮箱和密码'
      case 'otp required':
        return '请输入 OTP 验证码'
      case 'nickname required':
        return '请输入昵称'
      case 'email already exists':
        return '该邮箱已被注册'
      default:
        return serverMessage
    }
  } catch {
    return raw || fallback
  }
}

function useAppData() {
  const [user, setUser] = useState<User | null>(null)
  const [configState, setConfigState] = useState<AppConfig>({ allow_register: true })
  const [categories, setCategories] = useState<Category[]>([])
  const [links, setLinks] = useState<LinkItem[]>([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState<string | null>(null)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const me = await api<{ user: User | null; allow_register?: boolean }>('/api/auth/me')
      setUser(me.user || null)
      if (typeof me.allow_register === 'boolean') {
        setConfigState({ allow_register: me.allow_register })
      }
    } catch (error) {
      console.error(error)
      setUser(null)
    }
    try {
      const cs = await api<{ categories: Category[] }>('/api/categories')
      setCategories((cs.categories || []).filter((c) => c && typeof c.id !== 'undefined'))
      const ls = await api<{ links: LinkItem[] }>('/api/links')
      setLinks((ls.links || []).filter((l) => l && typeof l.id !== 'undefined'))
      setMessage(null)
    } catch (error) {
      console.error(error)
      setMessage('暂时无法同步最新数据，你仍然可以先登录后台后再重试。')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const promise = loadAll()
    void promise
  }, [loadAll])

  return { user, setUser, categories, setCategories, links, setLinks, loading, message, setMessage, loadAll, configState }
}

function HomePage({ user, categories, links, loading, handleLinkClick }: { user: User | null; categories: Category[]; links: LinkItem[]; loading: boolean; handleLinkClick: (l: LinkItem) => void }) {
  const [search, setSearch] = useState('')
  const filteredLinks = useMemo(() => {
    if (!search.trim()) return links
    const q = search.trim().toLowerCase()
    return links.filter((l) => l.title.toLowerCase().includes(q) || l.url.toLowerCase().includes(q))
  }, [links, search])
  const linksByCategory = useMemo(() => {
    const map = new Map<number, LinkItem[]>()
    filteredLinks.forEach((l) => {
      const arr = map.get(l.category_id) || []
      map.set(l.category_id, [...arr, l])
    })
    return map
  }, [filteredLinks])

  return (
    <div className="flex flex-col items-center w-full">
      {/* 搜索区：对标 demo .search-container */}
      <div className="mt-[80px] w-[80%] max-w-[600px] text-center">
        <h1 className="mb-[30px] text-3xl font-light tracking-wide text-gray-700">探索发现</h1>
        <div className="relative w-full">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="输入搜索内容..."
            // 对标 demo .search-box：纯白背景、无边框、特定阴影、移除 focus:ring
            className="w-full py-[15px] px-[25px] rounded-[30px] border-none shadow-[0_4px_6px_rgba(0,0,0,0.08)] text-[16px] outline-none placeholder-gray-400 focus:shadow-[0_6px_10px_rgba(0,0,0,0.1)] transition-shadow duration-300"
            style={{ backgroundColor: '#fff' }}
            autoFocus
          />
        </div>
        {!user && <p className="mt-4 text-xs text-gray-400">未登录仅显示公开链接</p>}
      </div>

      {loading && <div className="mt-10 text-sm text-gray-500">加载中...</div>}
      {!loading && (
        // 对标 demo .main-content
        <div className="mt-[50px] w-[90%] max-w-[900px]">
          {categories
            .slice()
            .sort((a, b) => a.sort_order - b.sort_order)
            .map((cat) => {
              const catLinks = (linksByCategory.get(cat.id) || []).sort((a, b) => a.sort_order - b.sort_order)
              return (
                <div key={cat.id} className="mb-10">
                  {/* 对标 demo .category-title：左侧蓝色竖条 (#4a90e2) */}
                  <div className="mb-[20px] border-l-4 border-[#4a90e2] pl-[12px] text-[1.2rem] font-bold text-[#333]">
                    {cat.name}
                    {cat.description && <span className="ml-2 text-sm font-normal text-gray-500">{cat.description}</span>}
                  </div>

                  {/* 对标 demo .grid-container */}
                  <div 
                    className="grid gap-[25px] mb-[50px] grid-container-custom"
                  >
                    {catLinks.map((link) => (
                      <a
                        key={link.id}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={() => handleLinkClick(link)}
                        // 对标 demo .link-card：白色卡片、左图右文
                        className="flex items-center bg-white p-[18px] rounded-[12px] text-gray-700 shadow-[0_4px_6px_rgba(0,0,0,0.05)] transition-all duration-300 hover:-translate-y-[4px] hover:shadow-[0_10px_20px_rgba(0,0,0,0.1)] group"
                      >
                        {link.icon_url ? (
                          <img src={link.icon_url} alt="" className="w-[24px] h-[24px] mr-[12px] rounded-[4px] opacity-90 group-hover:opacity-100 transition-opacity" />
                        ) : (
                          <div className="w-[24px] h-[24px] mr-[12px] rounded-[4px] bg-accent/10 flex items-center justify-center text-xs text-accent font-bold">{link.title[0]}</div>
                        )}
                        <span className="truncate text-[15px]">{link.title}</span>
                        {!link.is_public && <span className="ml-auto rounded-full bg-gray-100 px-2 text-xs text-gray-500">私有</span>}
                      </a>
                    ))}
                    {catLinks.length === 0 && <div className="text-sm text-gray-500 col-span-full">暂无链接，去后台添加吧。</div>}
                  </div>
                </div>
              )
            })}
        </div>
      )}
    </div>
  )
}

function AdminPage({
  user,
  setUser,
  allowRegister,
  onBindGitHub,
  onBindGoogle,
  categories,
  setCategories,
  links,
  setLinks,
  message,
  setMessage,
  loadAll,
}: {
  user: User | null
  setUser: (u: User | null) => void
  allowRegister: boolean
  onBindGitHub: () => Promise<void>
  onBindGoogle: () => Promise<void>
  categories: Category[]
  setCategories: (v: Category[]) => void
  links: LinkItem[]
  setLinks: (v: LinkItem[]) => void
  message: string | null
  setMessage: (v: string | null) => void
  loadAll: () => Promise<void>
}) {
  const [tab, setTab] = useState<'categories' | 'links' | 'profile'>('categories')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [authForm, setAuthForm] = useState({ email: '', password: '', nickname: '', otp: '' })
  const [editingCategory, setEditingCategory] = useState<Category | null>(null)
  const [editingLink, setEditingLink] = useState<LinkItem | null>(null)
  const [totpInfo, setTotpInfo] = useState<{ secret?: string; url?: string } | null>(null)
  const [categoryForm, setCategoryForm] = useState({ name: '', description: '', sort_order: 0 })
  const [linkForm, setLinkForm] = useState({ category_id: '', title: '', url: '', is_public: true, sort_order: 0, icon_url: '', remark: '' })
  const [pwdForm, setPwdForm] = useState({ old_password: '', new_password: '', confirm: '' })
  const [profileLoading, setProfileLoading] = useState(false)

  const showMessage = useCallback((msg: string) => {
    setMessage(msg)
    setTimeout(() => setMessage(null), 3000)
  }, [setMessage])

  const handleEditCategory = (cat: Category) => {
    setEditingCategory(cat)
  }

  const handleUpdateCategory = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingCategory) return
    try {
      await api(`/api/categories/${editingCategory.id}`, { method: 'PUT', body: JSON.stringify(editingCategory) })
      showMessage('分类已更新')
      setEditingCategory(null)
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '更新分类失败'))
    }
  }

  const handleDeleteCategory = async (cat: Category) => {
    if (!window.confirm(`确认删除分类「${cat.name}」及其下链接？`)) return
    try {
      await api(`/api/categories/${cat.id}`, { method: 'DELETE' })
      showMessage('分类已删除')
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '删除分类失败'))
    }
  }

  const handleEditLink = (link: LinkItem) => {
    setEditingLink(link)
  }

  const handleUpdateLink = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingLink) return
    try {
      await api(`/api/links/${editingLink.id}`, { method: 'PUT', body: JSON.stringify(editingLink) })
      showMessage('链接已更新')
      setEditingLink(null)
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '更新链接失败'))
    }
  }

  const handleDeleteLink = async (link: LinkItem) => {
    if (!window.confirm(`确认删除链接「${link.title}」？`)) return
    try {
      await api(`/api/links/${link.id}`, { method: 'DELETE' })
      showMessage('链接已删除')
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '删除链接失败'))
    }
  }

  const handleAuthSubmit = async () => {
    try {
      if (authMode === 'register' && allowRegister) {
        const res = await api<{ user: User; totp_secret: string; totp_url: string }>('/api/auth/register', {
          method: 'POST',
          body: JSON.stringify({ email: authForm.email, password: authForm.password, nickname: authForm.nickname }),
        })
        setUser(res.user)
        setTotpInfo({ secret: res.totp_secret, url: res.totp_url })
        showMessage('注册成功，请在认证器中添加 TOTP')
      } else {
        const res = await api<{ user: User }>('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email: authForm.email, password: authForm.password, otp: authForm.otp }),
        })
        setUser(res.user)
        setTotpInfo(null)
        showMessage('登录成功')
      }
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '认证失败'))
    }
  }

  const handleLogout = async () => {
    await api('/api/auth/logout', { method: 'POST' })
    setUser(null)
    showMessage('已退出')
  }

  const handleChangePassword = async () => {
    if (pwdForm.new_password !== pwdForm.confirm) {
      showMessage('两次输入的密码不一致')
      return
    }
    try {
      await api('/api/auth/password', { method: 'POST', body: JSON.stringify({ old_password: pwdForm.old_password, new_password: pwdForm.new_password }) })
      showMessage('密码已更新')
      setPwdForm({ old_password: '', new_password: '', confirm: '' })
    } catch (error) {
      showMessage(getErrorMessage(error, '修改密码失败'))
    }
  }

  const handleGitHubLogin = async () => {
    try {
      const res = await api<{ url: string }>('/api/auth/github/start')
      window.location.href = res.url
    } catch (error) {
      showMessage(getErrorMessage(error, 'GitHub 登录配置缺失'))
    }
  }

  const handleGoogleLogin = async () => {
    try {
      const res = await api<{ url: string }>('/api/auth/google/start')
      window.location.href = res.url
    } catch (error) {
      showMessage(getErrorMessage(error, 'Google 登录配置缺失'))
    }
  }

  const loadTotp = useCallback(async () => {
    setProfileLoading(true)
    try {
      const res = await api<{ secret: string; url: string }>('/api/auth/totp')
      setTotpInfo(res)
    } catch (error) {
      showMessage(getErrorMessage(error, '获取 TOTP 失败'))
    } finally {
      setProfileLoading(false)
    }
  }, [showMessage])

  useEffect(() => {
    if (!allowRegister && authMode === 'register') {
      setAuthMode('login')
    }
  }, [allowRegister, authMode])

  useEffect(() => {
    if (tab === 'profile' && user) {
      void loadTotp()
    }
  }, [loadTotp, tab, user])

  const handleCreateCategory = async () => {
    try {
      await api('/api/categories', { method: 'POST', body: JSON.stringify(categoryForm) })
      setCategoryForm({ name: '', description: '', sort_order: 0 })
      showMessage('分类已创建')
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '创建分类失败'))
    }
  }

  const handleCreateLink = async () => {
    try {
      const payload = { ...linkForm, category_id: Number(linkForm.category_id) }
      await api('/api/links', { method: 'POST', body: JSON.stringify(payload) })
      setLinkForm({ category_id: '', title: '', url: '', is_public: true, sort_order: 0, icon_url: '', remark: '' })
      showMessage('链接已创建')
      await loadAll()
    } catch (error) {
      showMessage(getErrorMessage(error, '创建链接失败'))
    }
  }

  const onDragEnd = async (result: DropResult) => {
    if (!result.destination) return
    if (result.type === 'category') {
      const updated = Array.from(categories)
      const [removed] = updated.splice(result.source.index, 1)
      updated.splice(result.destination.index, 0, removed)
      const reordered = updated.map((c, idx) => ({ ...c, sort_order: idx }))
      setCategories(reordered)
      try {
        await api('/api/categories/reorder', { method: 'PUT', body: JSON.stringify(reordered.map((c) => ({ id: c.id, sort_order: c.sort_order }))) })
      } catch (error) {
        showMessage(getErrorMessage(error, '分类排序失败'))
      }
      return
    }
    if (result.type === 'link') {
      const catId = Number(result.source.droppableId.replace('links-', ''))
      const catLinks = links.filter((l) => l.category_id === catId)
      const others = links.filter((l) => l.category_id !== catId)
      const ordered = Array.from(catLinks)
      const [removed] = ordered.splice(result.source.index, 1)
      ordered.splice(result.destination.index, 0, removed)
      const reordered = ordered.map((l, idx) => ({ ...l, sort_order: idx }))
      setLinks([...others, ...reordered])
      try {
        await api('/api/links/reorder', { method: 'PUT', body: JSON.stringify(reordered.map((l) => ({ id: l.id, sort_order: l.sort_order }))) })
      } catch (error) {
        showMessage(getErrorMessage(error, '链接排序失败'))
      }
    }
  }

  const containerClass = user ? "grid gap-6 lg:grid-cols-[220px_1fr]" : "max-w-xl mx-auto space-y-4";

  return (
    <div className={containerClass}>
      {user && (
        <>
          <button
            onClick={() => setMobileNavOpen(true)}
            className="lg:hidden fixed left-3 top-24 z-40 flex h-10 w-10 items-center justify-center rounded-full bg-accent text-white shadow-lg"
            aria-label="打开菜单"
          >
            ☰
          </button>
          <aside className="hidden h-fit w-[240px] rounded-2xl bg-white p-5 shadow-lg lg:block sticky top-8">
            <nav className="flex flex-col gap-2 text-sm font-medium text-gray-600">
              <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'categories' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => setTab('categories')}>
                <span>📁</span> 分类管理
              </button>
              <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'links' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => setTab('links')}>
                <span>🔗</span> 链接管理
              </button>
              <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'profile' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => setTab('profile')}>
                <span>👤</span> 个人信息
              </button>
            </nav>
          </aside>

          {mobileNavOpen && (
            <div className="fixed inset-0 z-50 flex">
              <div className="w-64 h-full bg-white shadow-2xl p-5 flex flex-col gap-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-sm font-semibold text-gray-700">菜单</div>
                  <button onClick={() => setMobileNavOpen(false)} className="text-gray-500 hover:text-gray-800">✕</button>
                </div>
                <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'categories' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => { setTab('categories'); setMobileNavOpen(false) }}>
                  <span>📁</span> 分类管理
                </button>
                <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'links' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => { setTab('links'); setMobileNavOpen(false) }}>
                  <span>🔗</span> 链接管理
                </button>
                <button className={`flex items-center gap-3 rounded-xl px-4 py-3 transition-colors ${tab === 'profile' ? 'bg-accent/10 text-accent' : 'hover:bg-accent/10 hover:text-accent'}`} onClick={() => { setTab('profile'); setMobileNavOpen(false) }}>
                  <span>👤</span> 个人信息
                </button>
              </div>
              <div className="flex-1" onClick={() => setMobileNavOpen(false)}></div>
            </div>
          )}
        </>
      )}

      <div className="space-y-4">
        {message && (
          <div className={`rounded-lg px-3 py-2 text-sm ${user ? 'bg-accent/10 text-accent' : 'border border-amber-200 bg-amber-50 text-amber-700'}`}>
            {message}
          </div>
        )}
        {!user && (
          <div className="relative overflow-hidden rounded-[28px] border border-white/70 bg-white/95 p-6 shadow-[0_24px_60px_rgba(74,144,226,0.12)] backdrop-blur sm:p-8">
            <div className="pointer-events-none absolute inset-x-6 top-0 h-px bg-gradient-to-r from-transparent via-accent/50 to-transparent" />
            <div className="pointer-events-none absolute -right-20 -top-24 h-52 w-52 rounded-full bg-accent/10 blur-3xl" />
            <div className="pointer-events-none absolute -left-24 bottom-0 h-44 w-44 rounded-full bg-sky-100/70 blur-3xl" />

            <div id="admin-account" className="relative mx-auto max-w-md">
              <div className="mb-8 space-y-3 text-center">
                <div className="inline-flex items-center rounded-full border border-accent/15 bg-accent/10 px-3 py-1 text-[11px] font-semibold tracking-[0.28em] text-accent">ROC NAV ADMIN</div>
                <div className="space-y-2">
                  <h3 className="text-3xl font-semibold tracking-[0.08em] text-gray-800">登录后台</h3>
                  <p className="text-sm leading-6 text-gray-500">管理分类、维护链接和个人设置。使用你的账号密码与动态验证码登录。</p>
                </div>
              </div>

              <div className="space-y-4">
                <input className="w-full rounded-2xl border border-gray-200 bg-white/90 px-4 py-3 text-sm text-gray-700 outline-none transition-all placeholder:text-gray-400 focus:border-accent focus:ring-2 focus:ring-accent/20" placeholder="邮箱" value={authForm.email} onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })} />
                <input className="w-full rounded-2xl border border-gray-200 bg-white/90 px-4 py-3 text-sm text-gray-700 outline-none transition-all placeholder:text-gray-400 focus:border-accent focus:ring-2 focus:ring-accent/20" placeholder="密码" type="password" value={authForm.password} onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} />
                {allowRegister && authMode === 'register' && (
                  <input className="w-full rounded-2xl border border-gray-200 bg-white/90 px-4 py-3 text-sm text-gray-700 outline-none transition-all placeholder:text-gray-400 focus:border-accent focus:ring-2 focus:ring-accent/20" placeholder="昵称" value={authForm.nickname} onChange={(e) => setAuthForm({ ...authForm, nickname: e.target.value })} />
                )}
                {authMode === 'login' && (
                  <input className="w-full rounded-2xl border border-gray-200 bg-white/90 px-4 py-3 text-sm text-gray-700 outline-none transition-all placeholder:text-gray-400 focus:border-accent focus:ring-2 focus:ring-accent/20" placeholder="一次性验证码（OTP）" value={authForm.otp} onChange={(e) => setAuthForm({ ...authForm, otp: e.target.value })} />
                )}
              </div>

              <div className="mt-6 space-y-3">
                <button onClick={handleAuthSubmit} className="w-full rounded-2xl bg-accent px-4 py-3 text-sm font-medium tracking-[0.12em] text-white shadow-[0_18px_30px_rgba(74,144,226,0.24)] transition-all hover:-translate-y-0.5 hover:bg-[#3f83d2]">{authMode === 'register' ? '立即注册' : '进入后台'}</button>
                {allowRegister && (
                  <button onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')} className="w-full rounded-2xl border border-gray-200 bg-bodybg/80 px-4 py-3 text-sm font-medium text-gray-600 transition-colors hover:border-accent/30 hover:text-accent">切换到 {authMode === 'login' ? '注册' : '登录'}</button>
                )}
              </div>

              <div className="my-6 flex items-center gap-4 text-xs tracking-[0.24em] text-gray-400">
                <div className="h-px flex-1 bg-gradient-to-r from-transparent to-gray-200" />
                <span>第三方登录</span>
                <div className="h-px flex-1 bg-gradient-to-l from-transparent to-gray-200" />
              </div>

              <div className="grid gap-3 sm:grid-cols-2">
                <button
                  onClick={handleGoogleLogin}
                  className="flex w-full items-center justify-center gap-3 rounded-2xl border border-[#dadce0] bg-white px-4 py-3 text-sm font-medium text-[#3c4043] shadow-[0_1px_2px_rgba(60,64,67,0.15)] transition-all hover:-translate-y-0.5 hover:shadow-[0_4px_10px_rgba(60,64,67,0.18)]"
                >
                  <span className="flex h-5 w-5 items-center justify-center">
                    <svg viewBox="0 0 18 18" className="h-5 w-5" aria-hidden="true">
                      <path fill="#EA4335" d="M9 7.364v3.517h4.887c-.215 1.131-.859 2.089-1.827 2.733l2.955 2.295c1.722-1.586 2.713-3.924 2.713-6.709 0-.643-.058-1.26-.164-1.836H9Z" />
                      <path fill="#4285F4" d="M9 18c2.43 0 4.468-.806 5.957-2.191l-2.955-2.295c-.806.542-1.836.864-3.002.864-2.302 0-4.252-1.554-4.949-3.635H.999v2.37A9 9 0 0 0 9 18Z" />
                      <path fill="#FBBC05" d="M4.051 10.743A5.41 5.41 0 0 1 3.776 9c0-.605.106-1.186.275-1.743V4.887H.999A9 9 0 0 0 0 9c0 1.447.346 2.814.999 4.113l3.052-2.37Z" />
                      <path fill="#34A853" d="M9 3.622c1.321 0 2.506.454 3.438 1.342l2.58-2.58C13.464.942 11.426 0 9 0A9 9 0 0 0 .999 4.887l3.052 2.37C4.748 5.176 6.698 3.622 9 3.622Z" />
                    </svg>
                  </span>
                  <span>Sign in with Google</span>
                </button>
                <button onClick={handleGitHubLogin} className="flex w-full items-center justify-center gap-3 rounded-2xl border border-gray-900 bg-gray-950 px-4 py-3 text-sm font-medium text-white shadow-sm transition-all hover:-translate-y-0.5 hover:bg-black">
                  <span className="text-base">◎</span>
                  GitHub
                </button>
              </div>

              {totpInfo && (
                <div className="mt-5 rounded-2xl border border-accent/15 bg-accent/5 p-4 text-xs text-gray-600">
                  <div className="mb-2 text-[11px] font-semibold tracking-[0.22em] text-accent">TOTP SETUP</div>
                  <div>请在 Google Authenticator 中添加：</div>
                  <div className="mt-2 font-mono break-all text-gray-800">{totpInfo.secret}</div>
                  <div className="mt-1 font-mono break-all text-gray-800">{totpInfo.url}</div>
                </div>
              )}
            </div>
          </div>
        )}
      {user && tab === 'categories' && (
        <div className="space-y-6">
          <div className="rounded-2xl bg-white p-6 shadow-lg">
            <h3 className="mb-4 text-xl font-bold text-gray-800">新增分类</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="分类名" value={categoryForm.name} onChange={(e) => setCategoryForm({ ...categoryForm, name: e.target.value })} />
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="分类描述" value={categoryForm.description} onChange={(e) => setCategoryForm({ ...categoryForm, description: e.target.value })} />
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="排序(数字)" type="number" value={categoryForm.sort_order} onChange={(e) => setCategoryForm({ ...categoryForm, sort_order: Number(e.target.value) })} />
              <button onClick={handleCreateCategory} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-white shadow-md hover:bg-opacity-90 transition-all active:scale-95">新建分类</button>
            </div>
          </div>

          <div className="rounded-2xl bg-white p-6 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-bold text-gray-800">分类列表</h3>
              <span className="text-xs text-gray-400">拖拽排序</span>
            </div>
            <DragDropContext onDragEnd={onDragEnd}>
              <Droppable droppableId="categories" type="category">
                {(provided) => (
                  <div ref={provided.innerRef} {...provided.droppableProps} className="flex flex-col gap-4">
                    {categories.sort((a, b) => a.sort_order - b.sort_order).map((cat, idx) => (
                      <Draggable draggableId={`cat-${cat.id}`} index={idx} key={cat.id}>
                        {(providedCat) => (
                          <div ref={providedCat.innerRef} {...providedCat.draggableProps} className="flex items-center gap-3 rounded-xl border border-gray-100 bg-gray-50 p-4 shadow-sm">
                            <span {...providedCat.dragHandleProps} className="inline-flex h-8 w-8 cursor-grab items-center justify-center rounded-lg bg-white text-gray-400 shadow-sm hover:text-accent">☰</span>
                            <div className="min-w-0">
                              <div className="font-semibold text-gray-800">{cat.name}</div>
                              {cat.description && <div className="text-sm text-gray-500 truncate">{cat.description}</div>}
                            </div>
                            <div className="ml-auto flex gap-2">
                              <button onClick={() => handleEditCategory(cat)} className="rounded-lg bg-white px-3 py-1.5 text-xs font-medium text-gray-600 shadow-sm hover:bg-gray-50">编辑</button>
                              <button onClick={() => handleDeleteCategory(cat)} className="rounded-lg bg-white px-3 py-1.5 text-xs font-medium text-red-500 shadow-sm hover:bg-red-50">删除</button>
                            </div>
                          </div>
                        )}
                      </Draggable>
                    ))}
                    {provided.placeholder}
                  </div>
                )}
              </Droppable>
            </DragDropContext>
          </div>
        </div>
      )}

      {user && tab === 'links' && (
        <div className="space-y-6">
          <div className="rounded-2xl bg-white p-6 shadow-lg">
            <h3 className="mb-4 text-xl font-bold text-gray-800">新增链接</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <select className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" value={linkForm.category_id} onChange={(e) => setLinkForm({ ...linkForm, category_id: e.target.value })}>
                <option value="">选择分类</option>
                {categories.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="标题" value={linkForm.title} onChange={(e) => setLinkForm({ ...linkForm, title: e.target.value })} />
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="URL" value={linkForm.url} onChange={(e) => setLinkForm({ ...linkForm, url: e.target.value })} />
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="图标 URL (可选)" value={linkForm.icon_url} onChange={(e) => setLinkForm({ ...linkForm, icon_url: e.target.value })} />
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="备注 (可选)" value={linkForm.remark} onChange={(e) => setLinkForm({ ...linkForm, remark: e.target.value })} />
              <div className="flex items-center gap-2 px-1">
                <input id="isPublic" type="checkbox" checked={linkForm.is_public} onChange={(e) => setLinkForm({ ...linkForm, is_public: e.target.checked })} className="h-5 w-5 rounded border-gray-300 text-accent focus:ring-accent" />
                <label htmlFor="isPublic" className="text-sm font-medium text-gray-700">公开</label>
              </div>
              <input className="w-full rounded-lg border border-gray-300 px-4 py-2.5 outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all" placeholder="排序(数字)" type="number" value={linkForm.sort_order} onChange={(e) => setLinkForm({ ...linkForm, sort_order: Number(e.target.value) })} />
              <button onClick={handleCreateLink} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-white shadow-md hover:bg-opacity-90 transition-all active:scale-95">新增链接</button>
            </div>
          </div>

          <div className="rounded-2xl bg-white p-6 shadow-lg space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-bold text-gray-800">链接拖拽排序</h3>
              <span className="text-xs text-gray-400">拖拽即可自动保存</span>
            </div>
            <DragDropContext onDragEnd={onDragEnd}>
              <Droppable droppableId="categories" type="category">
                {(provided) => (
                  <div ref={provided.innerRef} {...provided.droppableProps} className="flex flex-col gap-8">
                    {categories.sort((a, b) => a.sort_order - b.sort_order).map((cat, idx) => {
                      const catLinks = links
                        .filter((l) => l.category_id === cat.id)
                        .sort((a, b) => a.sort_order - b.sort_order)
                      return (
                        <Draggable draggableId={`cat-${cat.id}`} index={idx} key={cat.id}>
                          {(providedCat) => (
                            <div ref={providedCat.innerRef} {...providedCat.draggableProps} className="space-y-4 rounded-xl border border-gray-100 bg-gray-50 p-4 transition-shadow hover:shadow-md">
                              <div {...providedCat.dragHandleProps} className="flex items-center gap-3 text-lg font-semibold text-gray-700">
                                <span className="inline-flex h-8 w-8 cursor-grab items-center justify-center rounded-lg bg-white text-gray-400 shadow-sm hover:text-accent">☰</span>
                                <div>
                                  <div className="font-bold">{cat.name}</div>
                                  {cat.description && <div className="text-sm font-normal text-gray-500">{cat.description}</div>}
                                </div>
                                <div className="ml-auto flex gap-2">
                                  <button onClick={() => handleEditCategory(cat)} className="rounded-lg bg-white px-3 py-1.5 text-xs font-medium text-gray-600 shadow-sm hover:bg-gray-50">编辑</button>
                                  <button onClick={() => handleDeleteCategory(cat)} className="rounded-lg bg-white px-3 py-1.5 text-xs font-medium text-red-500 shadow-sm hover:bg-red-50">删除</button>
                                </div>
                              </div>
                              <Droppable droppableId={`links-${cat.id}`} type="link">
                                {(dropProvided) => (
                                  <div ref={dropProvided.innerRef} {...dropProvided.droppableProps} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                                    {catLinks.map((link, idx2) => (
                                      <Draggable draggableId={`link-${link.id}`} index={idx2} key={link.id}>
                                        {(dragProvided) => (
                                          <div
                                            ref={dragProvided.innerRef}
                                            {...dragProvided.draggableProps}
                                            {...dragProvided.dragHandleProps}
                                            className="flex items-center gap-3 rounded-lg bg-white p-3 shadow-sm border border-gray-100 hover:shadow-md transition-shadow cursor-grab"
                                          >
                                            {link.icon_url ? <img src={link.icon_url} alt="" className="h-6 w-6 rounded" /> : <div className="h-6 w-6 flex items-center justify-center rounded bg-accent/10 text-xs text-accent font-bold">{link.title[0]}</div>}
                                            <div className="flex flex-col min-w-0">
                                              <span className="truncate text-sm font-medium text-gray-700">{link.title}</span>
                                              <span className="truncate text-xs text-gray-400">{link.url}</span>
                                              {link.remark && <span className="truncate text-xs text-gray-500">{link.remark}</span>}
                                            </div>
                                            <div className="ml-auto flex flex-col items-end gap-1.5">
                                              {!link.is_public && <span className="rounded-full bg-yellow-50 px-1.5 py-0.5 text-[10px] text-yellow-600 border border-yellow-100">私有</span>}
                                              <div className="flex gap-1">
                                                <button onClick={(e) => { e.stopPropagation(); handleEditLink(link) }} className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100 hover:text-gray-700">编辑</button>
                                                <button onClick={(e) => { e.stopPropagation(); handleDeleteLink(link) }} className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-50 hover:text-red-600">删</button>
                                              </div>
                                            </div>
                                          </div>
                                        )}
                                      </Draggable>
                                    ))}
                                    {dropProvided.placeholder}
                                  </div>
                                )}
                              </Droppable>
                            </div>
                          )}
                        </Draggable>
                      )
                    })}
                    {provided.placeholder}
                  </div>
                )}
              </Droppable>
            </DragDropContext>
          </div>
        </div>
      )}

      {user && tab === 'profile' && (
        <div className="space-y-6">
          <div className="rounded-2xl bg-white p-6 shadow-lg">
            <h3 className="mb-4 text-xl font-bold text-gray-800">个人信息</h3>
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <div className="rounded-full bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700">{user.nickname || user.email}</div>
              <button onClick={handleLogout} className="rounded-lg bg-red-50 px-4 py-2 text-sm text-red-600 hover:bg-red-100 transition-colors">退出当前登录</button>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-3 rounded-xl border border-gray-100 p-4">
                <div className="text-sm font-semibold text-gray-800">修改密码</div>
                <input className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent" placeholder="旧密码" type="password" value={pwdForm.old_password} onChange={(e) => setPwdForm({ ...pwdForm, old_password: e.target.value })} />
                <input className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent" placeholder="新密码" type="password" value={pwdForm.new_password} onChange={(e) => setPwdForm({ ...pwdForm, new_password: e.target.value })} />
                <input className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none focus:border-accent focus:ring-1 focus:ring-accent" placeholder="确认新密码" type="password" value={pwdForm.confirm} onChange={(e) => setPwdForm({ ...pwdForm, confirm: e.target.value })} />
                <button onClick={handleChangePassword} className="w-full rounded-lg bg-accent px-3 py-2 text-sm font-medium text-white shadow-sm hover:bg-opacity-90">保存密码</button>
              </div>

              <div className="space-y-4 rounded-xl border border-gray-100 p-4">
                <div className="text-sm font-semibold text-gray-800">第三方账号绑定</div>
                <div className="space-y-3 rounded-lg border border-gray-100 bg-gray-50/80 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-gray-700">Google</div>
                      <p className="text-xs text-gray-500">绑定后可使用 Google 登录。</p>
                    </div>
                    {user.google_id ? <span className="rounded-full bg-green-50 px-2 py-1 text-[11px] text-green-600">已绑定</span> : <span className="rounded-full bg-gray-100 px-2 py-1 text-[11px] text-gray-500">未绑定</span>}
                  </div>
                  {user.google_id ? (
                    <div className="text-xs text-green-600 break-all">Google ID: {user.google_id}</div>
                  ) : (
                    <button onClick={onBindGoogle} className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:border-gray-300 hover:bg-gray-50">绑定 Google</button>
                  )}
                </div>
                <div className="space-y-3 rounded-lg border border-gray-100 bg-gray-50/80 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-gray-700">GitHub</div>
                      <p className="text-xs text-gray-500">绑定后可使用 GitHub 登录。</p>
                    </div>
                    {user.github_id ? <span className="rounded-full bg-green-50 px-2 py-1 text-[11px] text-green-600">已绑定</span> : <span className="rounded-full bg-gray-100 px-2 py-1 text-[11px] text-gray-500">未绑定</span>}
                  </div>
                  {user.github_id ? (
                    <div className="text-xs text-green-600 break-all">GitHub ID: {user.github_id}</div>
                  ) : (
                    <button onClick={onBindGitHub} className="w-full rounded-lg bg-black px-3 py-2 text-sm font-medium text-white shadow-sm hover:bg-gray-900">绑定 GitHub</button>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-6 space-y-3 rounded-xl border border-gray-100 p-4">
              <div className="flex items-center justify-between">
                <div className="text-sm font-semibold text-gray-800">TOTP</div>
                <button
                  onClick={async () => {
                    setProfileLoading(true)
                    try {
                      const res = await api<{ secret: string; url: string }>('/api/auth/totp')
                      setTotpInfo(res)
                    } catch (error) {
                      showMessage(getErrorMessage(error, '获取 TOTP 失败'))
                    } finally {
                      setProfileLoading(false)
                    }
                  }}
                  className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-opacity-90"
                >
                  刷新
                </button>
              </div>
              {profileLoading && <div className="text-xs text-gray-500">加载中...</div>}
              {totpInfo && (
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:gap-6">
                  {totpInfo.url && (
                    <img src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(totpInfo.url)}`} alt="TOTP QR" className="h-32 w-32 rounded border border-gray-200 bg-white p-2" />
                  )}
                  <div className="space-y-1 text-xs text-gray-700 break-all">
                    <div>Secret: {totpInfo.secret}</div>
                    <div className="break-all">URL: {totpInfo.url}</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      </div>

      <Modal isOpen={!!editingCategory} onClose={() => setEditingCategory(null)} title="编辑分类">
        <form onSubmit={handleUpdateCategory} className="flex flex-col gap-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">名称</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingCategory?.name || ''}
              onChange={(e) => setEditingCategory(prev => prev ? ({ ...prev, name: e.target.value }) : null)}
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">描述</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingCategory?.description || ''}
              onChange={(e) => setEditingCategory(prev => prev ? ({ ...prev, description: e.target.value }) : null)}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">排序</label>
            <input
              type="number"
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingCategory?.sort_order || 0}
              onChange={(e) => setEditingCategory(prev => prev ? ({ ...prev, sort_order: Number(e.target.value) }) : null)}
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={() => setEditingCategory(null)} className="rounded-lg bg-gray-100 px-4 py-2 text-sm text-gray-700 hover:bg-gray-200">取消</button>
            <button type="submit" className="rounded-lg bg-accent px-4 py-2 text-sm text-white shadow-md hover:bg-opacity-90">保存</button>
          </div>
        </form>
      </Modal>

      <Modal isOpen={!!editingLink} onClose={() => setEditingLink(null)} title="编辑链接">
        <form onSubmit={handleUpdateLink} className="flex flex-col gap-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">标题</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingLink?.title || ''}
              onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, title: e.target.value }) : null)}
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">URL</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingLink?.url || ''}
              onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, url: e.target.value }) : null)}
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">图标 URL</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingLink?.icon_url || ''}
              onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, icon_url: e.target.value }) : null)}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">备注</label>
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              value={editingLink?.remark || ''}
              onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, remark: e.target.value }) : null)}
            />
          </div>
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="mb-1 block text-sm font-medium text-gray-700">排序</label>
              <input
                type="number"
                className="w-full rounded-lg border border-gray-300 px-3 py-2 outline-none focus:border-accent focus:ring-1 focus:ring-accent"
                value={editingLink?.sort_order || 0}
                onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, sort_order: Number(e.target.value) }) : null)}
              />
            </div>
            <div className="flex items-center pt-6">
              <input
                id="editIsPublic"
                type="checkbox"
                checked={editingLink?.is_public || false}
                onChange={(e) => setEditingLink(prev => prev ? ({ ...prev, is_public: e.target.checked }) : null)}
                className="mr-2 h-4 w-4 rounded border-gray-300 text-accent focus:ring-accent"
              />
              <label htmlFor="editIsPublic" className="text-sm text-gray-700">公开</label>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={() => setEditingLink(null)} className="rounded-lg bg-gray-100 px-4 py-2 text-sm text-gray-700 hover:bg-gray-200">取消</button>
            <button type="submit" className="rounded-lg bg-accent px-4 py-2 text-sm text-white shadow-md hover:bg-opacity-90">保存</button>
          </div>
        </form>
      </Modal>
    </div>
  )
}

function Header({ user, onLogout }: { user: User | null; onLogout: () => void }) {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const { pathname } = useLocation()
  const showLoginLink = !user && pathname === '/'

  return (
    <header className="mb-6 flex items-center justify-end gap-3">
      {showLoginLink && (
        <Link to="/admin" className="rounded-lg bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm ring-1 ring-gray-200 hover:bg-gray-50">
          登录
        </Link>
      )}
      {user && (
        <>
          {pathname !== '/' && (
            <Link to="/" className="rounded-lg bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm ring-1 ring-gray-200 hover:bg-gray-50">返回首页</Link>
          )}
          <div className="relative">
            <button
              onClick={() => setIsMenuOpen((open) => !open)}
              className="flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm transition-colors hover:bg-gray-50"
            >
              {user.nickname || user.email}
              <svg className={`h-4 w-4 transition-transform ${isMenuOpen ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" /></svg>
            </button>
            {isMenuOpen && (
              <div className="absolute right-0 z-50 mt-2 w-32 rounded-lg bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5 animate-in fade-in zoom-in duration-200">
                <Link to="/admin#admin-account" className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100" onClick={() => setIsMenuOpen(false)}>个人信息</Link>
                <Link to="/admin" className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100" onClick={() => setIsMenuOpen(false)}>设置</Link>
                <button onClick={() => { setIsMenuOpen(false); onLogout() }} className="block w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50">退出</button>
              </div>
            )}
          </div>
        </>
      )}
    </header>
  )
}

function App() {
  const data = useAppData()

  const handleLinkClick = async (link: LinkItem) => {
    try {
      await api(`/api/links/${link.id}/click`, { method: 'POST' })
    } catch (error) {
      console.error(error)
    }
  }

  const handleLogout = async () => {
    await api('/api/auth/logout', { method: 'POST' })
    data.setUser(null)
  }

  const handleBindGitHub = async () => {
    try {
      const res = await api<{ url: string }>('/api/auth/github/start?bind=1')
      window.location.href = res.url
    } catch (error) {
      console.error(error)
    }
  }

  const handleBindGoogle = async () => {
    try {
      const res = await api<{ url: string }>('/api/auth/google/start?bind=1')
      window.location.href = res.url
    } catch (error) {
      console.error(error)
    }
  }

  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bodybg text-text">
        {/* 去除外层容器的 padding 和 max-w 限制，HomePage 自己控制布局 */}
        <div className="min-h-screen">
          <div className="mx-auto max-w-6xl px-4 py-8">
            <Header user={data.user} onLogout={handleLogout} />
          </div>
          <Routes>
            <Route path="/" element={<HomePage user={data.user} categories={data.categories} links={data.links} loading={data.loading} handleLinkClick={handleLinkClick} />} />
            <Route
              path="/admin"
              element={
                <AdminPage
                  user={data.user}
                  setUser={data.setUser}
                  allowRegister={data.configState.allow_register}
                  onBindGitHub={handleBindGitHub}
                  onBindGoogle={handleBindGoogle}
                  categories={data.categories}
                  setCategories={data.setCategories}
                  links={data.links}
                  setLinks={data.setLinks}
                  message={data.message}
                  setMessage={data.setMessage}
                  loadAll={data.loadAll}
                />
              }
            />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  )
}

export default App
