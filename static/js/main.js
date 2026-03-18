const state = {
    localIp: window.location.hostname || '127.0.0.1',
    servers: [],
    linkedOverview: {
        servers: [],
        clients: [],
    },
    linkedStream: null,
    linkedStreamRetryTimer: null,
    linkedRealtimeActive: false,
    linkedRealtimeEnabled: false,
    openLinkedRealtimeStream: null,
    linkedActionBusy: new Set(),
    linkedActionLogs: [],
    linkedLogFilterServerId: '',
    linkedBatchBusy: false,
    linkedBatchProgressHideTimer: null,
    linkedBatchProgress: {
        visible: false,
        processed: 0,
        total: 0,
        label: '批量处理中',
    },
    selectedDeploy: {
        serverId: '',
        portId: '',
        action: 'deploy-frpc',
    },
    consoleActions: [],
    pollTimer: null,
};

const PORT_PROTOCOLS_WITH_DOMAIN = new Set(['http', 'https']);
const SECURITY_PROFILE_STORAGE_KEY = 'frpc_security_profile';
const CONSOLE_ACTIONS_STORAGE_KEY = 'console_quick_actions';
const SECURITY_PROFILE_LABELS = {
    balanced: '推荐：基础加密（TLS + 密钥）',
    hybrid: '增强：加密 + 压缩',
    mtls: '严格：双向证书校验',
};
const DEFAULT_CONSOLE_ACTIONS = [
    { label: '打开控制脚本', command: 'sudo bash control.sh' },
    { label: '查看服务状态', command: 'sudo systemctl status frp-manager --no-pager' },
    { label: '查看服务日志', command: 'sudo journalctl -u frp-manager -n 120 --no-pager' },
    { label: '重启服务', command: 'sudo systemctl restart frp-manager' },
];

document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initModals();
    initForms();
    initServerActionDelegation();
    initLinkedActionDelegation();
    initLinkedRealtime();
    initTerminal();
    updateSecurityProfileHint(getSecurityProfile());

    await loadAuthMeta();
    await loadLocalIp();
    await loadServers(false);
    setTimeout(() => {
        loadServers(true);
    }, 200);
    state.pollTimer = setInterval(() => {
        loadServers(true);
    }, 10000);
});

async function loadAuthMeta() {
    try {
        const data = await apiRequest('/api/auth/status');
        const holder = document.getElementById('admin-user');
        if (holder) {
            holder.textContent = data.admin_user || '-';
        }
    } catch (_error) {
        const holder = document.getElementById('admin-user');
        if (holder) {
            holder.textContent = '-';
        }
    }
}

function initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    const panels = document.querySelectorAll('.tab-panel');
    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach((item) => {
                item.classList.remove('active');
            });
            panels.forEach((item) => {
                item.classList.remove('active');
            });

            tab.classList.add('active');
            const panelId = `${tab.dataset.tab}-panel`;
            const panel = document.getElementById(panelId);
            if (panel) {
                panel.classList.add('active');
            }
            updateLinkedRealtimeState(tab.dataset.tab === 'linked');
        });
    });
}

function initModals() {
    bindModalClose('frps-modal', ['close-frps-modal', 'cancel-frps-modal']);
    bindModalClose('port-modal', ['close-port-modal', 'cancel-port-modal']);
    bindModalClose('frpc-modal', ['close-frpc-modal']);
    bindModalClose('system-select-modal', ['close-system-modal']);
    bindModalClose('deploy-modal', ['close-deploy-modal']);
    bindModalClose('console-actions-modal', ['close-console-actions-modal']);
    bindModalClose('linked-batch-result-modal', ['close-linked-batch-result-modal', 'confirm-linked-batch-result-modal']);
}

function bindModalClose(modalId, triggerIds) {
    const modal = document.getElementById(modalId);
    if (!modal) {
        return;
    }

    triggerIds.forEach((id) => {
        const trigger = document.getElementById(id);
        if (trigger) {
            trigger.addEventListener('click', () => closeModal(modalId));
        }
    });

    modal.addEventListener('click', (event) => {
        if (event.target.classList.contains('modal')) {
            closeModal(modalId);
        }
    });
}

function initForms() {
    const frpsForm = document.getElementById('frps-form');
    const portForm = document.getElementById('port-form');
    const portProtocol = document.getElementById('port-protocol');
    const clearTerminal = document.getElementById('clear-terminal');
    const copyFrpc = document.getElementById('copy-frpc-config');
    const copyDeploy = document.getElementById('copy-deploy-command');
    const securityProfileSelect = document.getElementById('security-profile-select');

    if (frpsForm) {
        frpsForm.addEventListener('submit', saveFRPSServer);
    }
    if (portForm) {
        portForm.addEventListener('submit', savePortMapping);
    }
    if (portProtocol) {
        portProtocol.addEventListener('change', () => syncProtocolFields(portProtocol.value));
    }
    if (clearTerminal) {
        clearTerminal.addEventListener('click', clearTerminalOutput);
    }
    if (copyFrpc) {
        copyFrpc.addEventListener('click', async () => {
            const code = document.querySelector('#frpc-config-output code');
            if (!code) {
                return;
            }
            await copyText(code.textContent || '');
            showToast('内容已复制到剪贴板', 'success');
        });
    }
    if (copyDeploy) {
        copyDeploy.addEventListener('click', async () => {
            const code = document.querySelector('#deploy-command code');
            if (!code) {
                return;
            }
            await copyText(code.textContent || '');
            showToast('内容已复制到剪贴板', 'success');
        });
    }
    if (securityProfileSelect) {
        securityProfileSelect.value = getSecurityProfile();
        securityProfileSelect.addEventListener('change', () => {
            const normalized = normalizeSecurityProfile(securityProfileSelect.value);
            securityProfileSelect.value = normalized;
            saveSecurityProfile(normalized);
            updateSecurityProfileHint(normalized);
        });
    }

    document.querySelectorAll('.system-btn[data-system]').forEach((button) => {
        button.addEventListener('click', () => selectSystem(button.dataset.system));
    });
}

function normalizeSecurityProfile(profile) {
    const text = String(profile || '').trim().toLowerCase();
    if (text === 'hybrid' || text === 'double') {
        return 'hybrid';
    }
    if (text === 'mtls' || text === 'strict') {
        return 'mtls';
    }
    return 'balanced';
}

function getSecurityProfile() {
    const select = document.getElementById('security-profile-select');
    if (select && select.value) {
        return normalizeSecurityProfile(select.value);
    }
    try {
        return normalizeSecurityProfile(window.localStorage.getItem(SECURITY_PROFILE_STORAGE_KEY));
    } catch (_error) {
        return 'balanced';
    }
}

function saveSecurityProfile(profile) {
    try {
        window.localStorage.setItem(SECURITY_PROFILE_STORAGE_KEY, normalizeSecurityProfile(profile));
    } catch (_error) {
        return;
    }
}

function updateSecurityProfileHint(profile) {
    const hint = document.getElementById('frpc-security-profile-hint');
    if (!hint) {
        return;
    }
    const normalized = normalizeSecurityProfile(profile);
    hint.textContent = `当前加密方案：${SECURITY_PROFILE_LABELS[normalized] || SECURITY_PROFILE_LABELS.balanced}`;
}

function initServerActionDelegation() {
    const list = document.getElementById('frps-servers-list');
    const addServerButton = document.getElementById('add-frps-server');

    if (addServerButton) {
        addServerButton.addEventListener('click', () => openFRPSModal());
    }
    if (!list) {
        return;
    }

    list.addEventListener('click', async (event) => {
        const button = event.target.closest('button[data-action]');
        if (!button) {
            return;
        }

        const action = button.dataset.action;
        const serverId = button.dataset.serverId;
        const portId = button.dataset.portId;

        try {
            if (action === 'edit-server') {
                await editFRPSServer(serverId);
                return;
            }
            if (action === 'delete-server') {
                await deleteFRPSServer(serverId);
                return;
            }
            if (action === 'refresh-server') {
                await refreshServer(serverId);
                return;
            }
            if (action === 'add-port') {
                openPortModal(serverId);
                return;
            }
            if (action === 'edit-port') {
                openPortModalFromState(serverId, portId);
                return;
            }
            if (action === 'delete-port') {
                await deletePort(serverId, portId);
                return;
            }
            if (action === 'toggle-port') {
                await togglePort(serverId, portId);
                return;
            }
            if (action === 'generate-frpc') {
                await generateFRPC(serverId);
                return;
            }
            if (action === 'deploy-frps') {
                await showFRPSDeployCommand(serverId);
                return;
            }
            if (action === 'deploy-frpc') {
                showSystemSelect(serverId, portId, 'deploy-frpc');
                return;
            }
            if (action === 'check-port') {
                await checkPort(serverId, portId);
                return;
            }
            if (action === 'cleanup-frpc') {
                showSystemSelect(serverId, portId, 'cleanup-frpc');
                return;
            }
            if (action === 'cleanup-frps') {
                await showFRPSCleanupCommand(serverId);
            }
        } catch (error) {
            showToast(error.message || '操作失败', 'error');
        }
    });
}

function initTerminal() {
    const input = document.getElementById('terminal-input');
    const quickActionContainer = document.getElementById('console-quick-actions');
    const linkButtons = document.querySelectorAll('[data-console-action]');
    const manageButton = document.getElementById('manage-console-actions');
    const addItemButton = document.getElementById('add-console-action-item');
    const saveButton = document.getElementById('save-console-actions');
    const resetButton = document.getElementById('reset-console-actions');

    state.consoleActions = loadConsoleActions();
    renderConsoleQuickActions();

    if (quickActionContainer) {
        quickActionContainer.addEventListener('click', async (event) => {
            const button = event.target.closest('button[data-console-cmd-index]');
            if (!button) {
                return;
            }
            const index = Number.parseInt(button.dataset.consoleCmdIndex || '', 10);
            if (Number.isNaN(index)) {
                return;
            }
            await runConsoleActionByIndex(index);
        });
    }

    linkButtons.forEach((button) => {
        button.addEventListener('click', async () => {
            const action = String(button.dataset.consoleAction || '').trim();
            await runConsoleQuickAction(action);
        });
    });

    if (manageButton) {
        manageButton.addEventListener('click', () => {
            renderConsoleActionsEditor(state.consoleActions);
            openModal('console-actions-modal');
        });
    }

    if (addItemButton) {
        addItemButton.addEventListener('click', () => {
            const current = collectConsoleActionsFromEditor();
            current.push({ label: '', command: '' });
            renderConsoleActionsEditor(current);
        });
    }

    if (saveButton) {
        saveButton.addEventListener('click', () => {
            const edited = collectConsoleActionsFromEditor();
            if (!edited.length) {
                showToast('请至少保留一条快捷命令', 'warning');
                return;
            }
            state.consoleActions = edited;
            persistConsoleActions(state.consoleActions);
            renderConsoleQuickActions();
            closeModal('console-actions-modal');
            showToast('快捷命令已保存', 'success');
        });
    }

    if (resetButton) {
        resetButton.addEventListener('click', () => {
            state.consoleActions = DEFAULT_CONSOLE_ACTIONS.map((item) => ({ ...item }));
            persistConsoleActions(state.consoleActions);
            renderConsoleActionsEditor(state.consoleActions);
            renderConsoleQuickActions();
            showToast('已恢复默认快捷命令', 'success');
        });
    }

    if (!input) {
        return;
    }

    input.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            executeCommand(input.value);
            input.value = '';
        }
    });
}

function loadConsoleActions() {
    try {
        const raw = window.localStorage.getItem(CONSOLE_ACTIONS_STORAGE_KEY);
        if (!raw) {
            return DEFAULT_CONSOLE_ACTIONS.map((item) => ({ ...item }));
        }
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) {
            return DEFAULT_CONSOLE_ACTIONS.map((item) => ({ ...item }));
        }
        const normalized = parsed
            .map((item) => {
                const label = String(item?.label || '').trim();
                const command = String(item?.command || '').trim();
                if (!label || !command) {
                    return null;
                }
                return { label, command };
            })
            .filter((item) => Boolean(item));
        return normalized.length ? normalized : DEFAULT_CONSOLE_ACTIONS.map((item) => ({ ...item }));
    } catch (_error) {
        return DEFAULT_CONSOLE_ACTIONS.map((item) => ({ ...item }));
    }
}

function persistConsoleActions(actions) {
    const payload = Array.isArray(actions)
        ? actions.map((item) => ({ label: String(item.label || '').trim(), command: String(item.command || '').trim() }))
        : [];
    try {
        window.localStorage.setItem(CONSOLE_ACTIONS_STORAGE_KEY, JSON.stringify(payload));
    } catch (_error) {
        return;
    }
}

function renderConsoleQuickActions() {
    const container = document.getElementById('console-quick-actions');
    if (!container) {
        return;
    }
    if (!state.consoleActions.length) {
        container.innerHTML = '<span class="hint">暂无快捷命令</span>';
        return;
    }
    container.innerHTML = state.consoleActions
        .map(
            (item, index) =>
                `<button type="button" class="btn btn-sm ${index === 0 ? 'btn-primary' : 'btn-secondary'}" data-console-cmd-index="${index}">${safeHtml(item.label)}</button>`
        )
        .join('');
}

function renderConsoleActionsEditor(actions) {
    const list = document.getElementById('console-actions-editor-list');
    if (!list) {
        return;
    }
    const source = Array.isArray(actions) ? actions : [];
    list.innerHTML = source
        .map(
            (item, index) => `
            <div class="console-action-edit-item" data-console-edit-index="${index}">
                <input type="text" data-edit-field="label" value="${safeAttr(item.label || '')}" placeholder="按钮名称，例如：查看日志">
                <input type="text" data-edit-field="command" value="${safeAttr(item.command || '')}" placeholder="命令，例如：sudo journalctl -u frp-manager -n 120 --no-pager">
                <button type="button" class="btn btn-sm btn-danger" data-remove-console-item="${index}">删除</button>
            </div>
        `
        )
        .join('');

    list.querySelectorAll('button[data-remove-console-item]').forEach((button) => {
        button.addEventListener('click', () => {
            const targetIndex = Number.parseInt(button.dataset.removeConsoleItem || '', 10);
            if (Number.isNaN(targetIndex)) {
                return;
            }
            const current = collectConsoleActionsFromEditor();
            const next = current.filter((_item, index) => index !== targetIndex);
            renderConsoleActionsEditor(next);
        });
    });
}

function collectConsoleActionsFromEditor() {
    const list = document.getElementById('console-actions-editor-list');
    if (!list) {
        return [];
    }
    const rows = Array.from(list.querySelectorAll('.console-action-edit-item'));
    return rows
        .map((row) => {
            const labelInput = row.querySelector('input[data-edit-field="label"]');
            const commandInput = row.querySelector('input[data-edit-field="command"]');
            const label = String(labelInput?.value || '').trim();
            const command = String(commandInput?.value || '').trim();
            if (!label || !command) {
                return null;
            }
            return { label, command };
        })
        .filter((item) => Boolean(item));
}

async function runConsoleActionByIndex(index) {
    const target = state.consoleActions[index];
    if (!target) {
        showToast('快捷命令不存在', 'warning');
        return;
    }
    const command = String(target.command || '').trim();
    if (!command) {
        showToast('命令为空', 'warning');
        return;
    }
    const input = document.getElementById('terminal-input');
    if (input) {
        input.value = command;
        input.focus();
    }
    await copyText(command);
    appendConsoleLine(`已填入并复制命令: ${command}`);
    showToast('命令已复制，可直接粘贴执行', 'success');
}

async function runConsoleQuickAction(action) {
    if (action === 'open-home') {
        window.location.href = '/';
        return;
    }
    if (action === 'open-login') {
        window.location.href = '/login';
        return;
    }
    showToast('该快捷入口暂不支持此操作', 'warning');
}

function appendConsoleLine(text) {
    const output = document.getElementById('terminal-output');
    if (!output) {
        return;
    }
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.textContent = text;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}

function clearTerminalOutput() {
    const output = document.getElementById('terminal-output');
    if (!output) {
        return;
    }
    output.innerHTML = `
        <div class="terminal-line">内网连接面板控制台 v1.1</div>
        <div class="terminal-line">可点击上方快捷按钮自动填入并复制命令（仅记录，不执行）。</div>
    `;
}

async function loadLocalIp() {
    try {
        const data = await apiRequest('/api/meta/local-ip');
        if (data.local_ip) {
            state.localIp = data.local_ip;
        }
    } catch (_error) {
        // Keep fallback from hostname.
    }
}

async function loadServers(refresh = false) {
    try {
        const url = refresh ? '/api/frps/servers?refresh=1' : '/api/frps/servers';
        const servers = await apiRequest(url);
        state.servers = Array.isArray(servers) ? servers : [];
        renderServers(state.servers);
        if (refresh || !state.linkedRealtimeActive) {
            const loaded = await loadLinkedOverview(refresh, true);
            if (!loaded) {
                syncLinkedFromServers();
            }
        }
    } catch (error) {
        showToast(error.message || '加载服务端失败', 'error');
    }
}

function setLinkedLiveStatus(text) {
    const el = document.getElementById('linked-live-status');
    if (!el) {
        return;
    }
    el.textContent = `实时：${text}`;
}

function appendLinkedLog(message, type = 'info') {
    appendLinkedLogWithContext({ message, type });
}

function appendLinkedLogWithContext({ message, type = 'info', serverId = '', portId = '' }) {
    const holder = document.getElementById('linked-action-log');
    if (!holder) {
        return;
    }

    const now = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    state.linkedActionLogs.unshift({
        at: now,
        type: String(type || 'info'),
        message: String(message || '').trim(),
        serverId: String(serverId || '').trim(),
        portId: String(portId || '').trim(),
    });
    state.linkedActionLogs = state.linkedActionLogs.slice(0, 12);

    renderLinkedActionLogs();
}

function renderLinkedActionLogs() {
    const holder = document.getElementById('linked-action-log');
    if (!holder) {
        return;
    }
    const filterServerId = String(state.linkedLogFilterServerId || '').trim();
    const filtered = filterServerId
        ? state.linkedActionLogs.filter((item) => String(item.serverId || '').trim() === filterServerId)
        : state.linkedActionLogs;

    const lines = filtered
        .map((item) => `<div class="linked-log-item ${safeAttr(item.type)}">[${safeHtml(item.at)}] ${safeHtml(item.message)}</div>`)
        .join('');
    const emptyText = filterServerId ? '当前服务端暂无记录' : '暂无记录';
    const toolbar = `
        <div class="linked-log-toolbar">
            <div class="linked-log-title">联动操作记录</div>
            <div class="linked-log-controls">
                <select id="linked-log-filter"></select>
                <button type="button" class="btn btn-xs btn-outline" id="linked-log-clear">清空记录</button>
            </div>
        </div>
    `;
    const progress = `
        <div class="linked-progress" id="linked-progress" style="display:none;">
            <div class="linked-progress-meta" id="linked-progress-meta">批量处理中 0/0</div>
            <div class="linked-progress-track">
                <div class="linked-progress-fill" id="linked-progress-fill" style="width:0%;"></div>
            </div>
        </div>
    `;
    holder.innerHTML = `${toolbar}${progress}${lines || `<div class="linked-log-empty">${safeHtml(emptyText)}</div>`}`;
    bindLinkedLogControls();
    renderLinkedLogFilterOptions();
    applyLinkedBatchProgress();
}

function renderLinkedLogFilterOptions() {
    const select = document.getElementById('linked-log-filter');
    if (!select) {
        return;
    }
    const servers = Array.isArray(state.linkedOverview?.servers) ? state.linkedOverview.servers : [];
    const options = ['<option value="">全部服务端</option>'];
    servers.forEach((server) => {
        options.push(`<option value="${safeAttr(server.id)}">${safeHtml(server.name || server.id || '服务端')}</option>`);
    });
    select.innerHTML = options.join('');
    const selected = String(state.linkedLogFilterServerId || '').trim();
    if (selected && !servers.some((server) => String(server.id || '').trim() === selected)) {
        state.linkedLogFilterServerId = '';
    }
    select.value = String(state.linkedLogFilterServerId || '').trim();
}

function bindLinkedLogControls() {
    const select = document.getElementById('linked-log-filter');
    const clearBtn = document.getElementById('linked-log-clear');
    if (select) {
        select.onchange = () => {
            state.linkedLogFilterServerId = String(select.value || '').trim();
            renderLinkedActionLogs();
        };
    }
    if (clearBtn) {
        clearBtn.onclick = () => {
            state.linkedActionLogs = [];
            renderLinkedActionLogs();
        };
    }
}

function applyLinkedBatchProgress() {
    const wrapper = document.getElementById('linked-progress');
    const meta = document.getElementById('linked-progress-meta');
    const fill = document.getElementById('linked-progress-fill');
    if (!wrapper || !meta || !fill) {
        return;
    }
    const { visible, processed, total, label } = state.linkedBatchProgress;
    if (!visible) {
        wrapper.style.display = 'none';
        fill.style.width = '0%';
        meta.textContent = '批量处理中 0/0';
        return;
    }
    const safeTotal = Math.max(Number(total || 0), 0);
    const safeProcessed = Math.min(Math.max(Number(processed || 0), 0), safeTotal || Number(processed || 0));
    const percent = safeTotal > 0 ? Math.min(100, Math.round((safeProcessed / safeTotal) * 100)) : 0;
    wrapper.style.display = 'block';
    fill.style.width = `${percent}%`;
    meta.textContent = `${label} ${safeProcessed}/${safeTotal}`;
}

function setLinkedBatchProgress(visible, processed = 0, total = 0, label = '批量处理中') {
    if (state.linkedBatchProgressHideTimer) {
        window.clearTimeout(state.linkedBatchProgressHideTimer);
        state.linkedBatchProgressHideTimer = null;
    }
    state.linkedBatchProgress = {
        visible: Boolean(visible),
        processed: Number(processed || 0),
        total: Number(total || 0),
        label: String(label || '批量处理中'),
    };
    applyLinkedBatchProgress();
}

async function runLinkedBatchAction(serverId, items, label, runner) {
    if (state.linkedBatchBusy) {
        throw new Error('已有批量任务执行中，请稍后再试');
    }
    state.linkedBatchBusy = true;
    const queue = Array.isArray(items) ? items : [];
    const total = queue.length;
    let processed = 0;
    let okCount = 0;
    const failedNames = [];
    const details = [];

    setLinkedBatchProgress(true, 0, total, label);
    try {
        for (const item of queue) {
            try {
                const result = await runner(item);
                const ok = typeof result === 'object' && result !== null
                    ? Boolean(result.ok)
                    : result !== false;
                const message = typeof result === 'object' && result !== null
                    ? String(result.message || '').trim()
                    : '';
                if (ok) {
                    okCount += 1;
                } else {
                    failedNames.push(String(item?.name || item?.id || '').trim());
                }
                details.push({
                    name: String(item?.name || item?.id || '').trim() || String(item?.id || '').trim(),
                    ok,
                    message,
                });
            } catch (_error) {
                failedNames.push(String(item?.name || item?.id || '').trim());
                details.push({
                    name: String(item?.name || item?.id || '').trim() || String(item?.id || '').trim(),
                    ok: false,
                    message: '请求失败',
                });
            }
            processed += 1;
            setLinkedBatchProgress(true, processed, total, label);
        }
    } finally {
        state.linkedBatchProgressHideTimer = window.setTimeout(() => setLinkedBatchProgress(false), 1200);
        state.linkedBatchBusy = false;
    }

    const failed = failedNames.filter((name) => name).slice(0, 3);
    appendLinkedLogWithContext({
        message: `服务端 ${serverId} ${label}：成功 ${okCount}/${total}${failed.length ? `，失败 ${failed.join(', ')}` : ''}`,
        type: failed.length ? 'warning' : 'success',
        serverId,
    });
    return { total, okCount, failedCount: Math.max(total - okCount, 0), failed, details };
}

function showLinkedBatchResultModal(serverId, label, summary) {
    const title = document.getElementById('linked-batch-result-title');
    const summaryEl = document.getElementById('linked-batch-result-summary');
    const listEl = document.getElementById('linked-batch-result-list');
    if (!title || !summaryEl || !listEl) {
        return;
    }

    title.textContent = `${label}结果`;
    summaryEl.textContent = `服务端 ${serverId}：成功 ${summary.okCount}/${summary.total}，失败 ${summary.failedCount}`;
    const details = Array.isArray(summary.details) ? summary.details : [];
    if (!details.length) {
        listEl.innerHTML = '<div class="linked-result-item">暂无明细</div>';
    } else {
        listEl.innerHTML = details
            .map((item) => `
                <div class="linked-result-item ${item.ok ? 'success' : 'error'}">
                    <div class="linked-result-name">${safeHtml(item.name || '规则')}</div>
                    <div>${safeHtml(item.ok ? '成功' : '失败')} ${safeHtml(item.message || '')}</div>
                </div>
            `)
            .join('');
    }
    openModal('linked-batch-result-modal');
}

function setLinkedActionButtonBusy(button, busy) {
    if (!button) {
        return;
    }
    const key = `${button.dataset.linkedAction || ''}:${button.dataset.serverId || ''}:${button.dataset.portId || ''}`;
    if (busy) {
        state.linkedActionBusy.add(key);
        button.disabled = true;
        return;
    }
    state.linkedActionBusy.delete(key);
    button.disabled = false;
}

function isLinkedActionBusy(action, serverId = '', portId = '') {
    const key = `${String(action || '').trim()}:${String(serverId || '').trim()}:${String(portId || '').trim()}`;
    return state.linkedActionBusy.has(key);
}

function linkedActionDisabledAttr(action, serverId = '', portId = '') {
    return isLinkedActionBusy(action, serverId, portId) ? ' disabled' : '';
}

function initLinkedRealtime() {
    if (typeof window.EventSource !== 'function') {
        setLinkedLiveStatus('浏览器不支持，使用轮询');
        return;
    }

    const openStream = () => {
        if (!state.linkedRealtimeEnabled) {
            return;
        }
        if (state.linkedStream) {
            try {
                state.linkedStream.close();
            } catch (_error) {
                state.linkedStream = null;
            }
            state.linkedStream = null;
        }

        setLinkedLiveStatus('连接中');
        const stream = new window.EventSource('/api/linked/stream');
        state.linkedStream = stream;

        stream.addEventListener('overview', (event) => {
            try {
                const payload = JSON.parse(String(event.data || '{}'));
                state.linkedOverview = {
                    servers: Array.isArray(payload?.servers) ? payload.servers : [],
                    clients: Array.isArray(payload?.clients) ? payload.clients : [],
                };
                state.linkedRealtimeActive = true;
                if (state.linkedStreamRetryTimer) {
                    window.clearTimeout(state.linkedStreamRetryTimer);
                    state.linkedStreamRetryTimer = null;
                }
                renderLinkedOverview();
                setLinkedLiveStatus('已连接');
            } catch (_error) {
                setLinkedLiveStatus('数据解析失败，使用轮询');
                state.linkedRealtimeActive = false;
            }
        });

        stream.addEventListener('heartbeat', () => {
            state.linkedRealtimeActive = true;
            if (state.linkedStreamRetryTimer) {
                window.clearTimeout(state.linkedStreamRetryTimer);
                state.linkedStreamRetryTimer = null;
            }
            setLinkedLiveStatus('已连接');
        });

        stream.onerror = () => {
            state.linkedRealtimeActive = false;
            setLinkedLiveStatus('连接中断，5秒后重连');
            try {
                stream.close();
            } catch (_error) {
                state.linkedRealtimeActive = false;
            }
            if (state.linkedStreamRetryTimer) {
                window.clearTimeout(state.linkedStreamRetryTimer);
            }
            state.linkedStreamRetryTimer = window.setTimeout(() => {
                if (state.linkedRealtimeEnabled) {
                    openStream();
                }
            }, 5000);
        };
    };

    state.openLinkedRealtimeStream = openStream;
    updateLinkedRealtimeState(false);

    window.addEventListener('beforeunload', () => {
        if (state.linkedStream) {
            try {
                state.linkedStream.close();
            } catch (_error) {
                state.linkedStream = null;
            }
        }
    });
}

function updateLinkedRealtimeState(enabled) {
    const shouldEnable = Boolean(enabled);
    state.linkedRealtimeEnabled = shouldEnable;

    if (!shouldEnable) {
        state.linkedRealtimeActive = false;
        if (state.linkedStreamRetryTimer) {
            window.clearTimeout(state.linkedStreamRetryTimer);
            state.linkedStreamRetryTimer = null;
        }
        if (state.linkedStream) {
            try {
                state.linkedStream.close();
            } catch (_error) {
                state.linkedStream = null;
            }
            state.linkedStream = null;
        }
        setLinkedLiveStatus('仅联动页连接');
        return;
    }

    if (!state.linkedStream && typeof state.openLinkedRealtimeStream === 'function') {
        state.openLinkedRealtimeStream();
    }
}

async function loadLinkedOverview(refresh = false, silent = true) {
    try {
        const query = refresh ? '?refresh=1' : '';
        const data = await apiRequest(`/api/linked/overview${query}`);
        state.linkedOverview = {
            servers: Array.isArray(data?.servers) ? data.servers : [],
            clients: Array.isArray(data?.clients) ? data.clients : [],
        };
        renderLinkedOverview();
        return true;
    } catch (error) {
        if (!silent) {
            showToast(error.message || '加载联动列表失败', 'error');
        }
        return false;
    }
}

function syncLinkedFromServers() {
    const linkedServers = [];
    const linkedClients = [];
    state.servers.forEach((server) => {
        const ports = Array.isArray(server?.ports) ? server.ports : [];
        linkedServers.push({
            id: server.id,
            name: server.name,
            status: server.status,
            server_addr: server.server_addr,
            server_port: server.server_port,
            ports_total: ports.length,
            ports_enabled: ports.filter((port) => port?.enabled !== false).length,
        });

        ports.forEach((port) => {
            linkedClients.push({
                id: port.id,
                server_id: server.id,
                server_name: server.name,
                name: port.name,
                protocol: port.protocol,
                enabled: port.enabled !== false,
                local_ip: port.local_ip,
                local_port: port.local_port,
                remote_port: port.remote_port,
                domain: port.domain,
                last_check_ok: Boolean(port.last_check_ok),
                last_check_message: port.last_check_message,
                last_check_at: port.last_check_at,
            });
        });
    });

    state.linkedOverview = {
        servers: linkedServers,
        clients: linkedClients,
    };
    renderLinkedOverview();
}

function renderLinkedOverview() {
    const serverList = document.getElementById('linked-servers-list');
    const clientList = document.getElementById('linked-clients-list');
    if (!serverList || !clientList) {
        return;
    }

    const linkedServers = Array.isArray(state.linkedOverview?.servers) ? state.linkedOverview.servers : [];
    const linkedClients = Array.isArray(state.linkedOverview?.clients) ? state.linkedOverview.clients : [];

    if (!linkedServers.length) {
        serverList.innerHTML = '<p class="no-ports">暂无服务端</p>';
    } else {
        serverList.innerHTML = linkedServers.map((server) => renderLinkedServerItem(server)).join('');
    }

    if (!linkedClients.length) {
        clientList.innerHTML = '<p class="no-ports">暂无客户端规则</p>';
    } else {
        clientList.innerHTML = linkedClients.map((client) => renderLinkedClientItem(client)).join('');
    }

    renderLinkedActionLogs();
}

function renderLinkedServerItem(server) {
    const serverId = safeAttr(server.id);
    const serverAddr = String(server.server_addr || '').trim();
    const status = String(server.status || 'unknown').trim();
    const statusMap = {
        online: '在线',
        offline: '离线',
        pending: '待部署',
        unknown: '检测中',
    };

    return `
        <div class="linked-item linked-server-item">
            <div class="linked-item-head">
                <span class="server-name">${safeHtml(server.name || '服务端')}</span>
                <span class="port-protocol">${safeHtml(statusMap[status] || '未知')}</span>
            </div>
            <div class="server-address">${safeHtml(serverAddr || '待部署后自动识别')} : ${safeHtml(server.server_port)}</div>
            <div class="linked-meta">规则总数 ${safeHtml(server.ports_total)} / 启用 ${safeHtml(server.ports_enabled)}</div>
            <div class="linked-actions">
                <button class="btn btn-xs btn-secondary" data-linked-action="linked-server-check" data-server-id="${serverId}"${linkedActionDisabledAttr('linked-server-check', server.id)}>检查服务端</button>
                <button class="btn btn-xs btn-secondary" data-linked-action="linked-server-check-clients" data-server-id="${serverId}"${linkedActionDisabledAttr('linked-server-check-clients', server.id)}>检查客户端</button>
                <button class="btn btn-xs btn-warning" data-linked-action="linked-server-shutdown" data-server-id="${serverId}"${linkedActionDisabledAttr('linked-server-shutdown', server.id)}>一键关闭</button>
                <button class="btn btn-xs btn-outline" data-linked-action="linked-server-edit" data-server-id="${serverId}"${linkedActionDisabledAttr('linked-server-edit', server.id)}>修改端口</button>
                <button class="btn btn-xs btn-danger" data-linked-action="linked-server-delete" data-server-id="${serverId}"${linkedActionDisabledAttr('linked-server-delete', server.id)}>删除数据</button>
            </div>
        </div>
    `;
}

function renderLinkedClientItem(client) {
    const serverId = safeAttr(client.server_id);
    const clientId = safeAttr(client.id);
    const enabled = client.enabled !== false;
    const protocol = String(client.protocol || 'tcp').toLowerCase();
    const checkText = client.last_check_at
        ? `${client.last_check_ok ? '检测可用' : '检测异常'} ${safeHtml(client.last_check_message || '')}`
        : '未检测';
    const mapping = PORT_PROTOCOLS_WITH_DOMAIN.has(protocol)
        ? `${safeHtml(client.local_ip)}:${safeHtml(client.local_port)} -> ${safeHtml(client.domain || '(未配置域名)')}`
        : `${safeHtml(client.local_ip)}:${safeHtml(client.local_port)} -> :${safeHtml(client.remote_port)}`;

    return `
        <div class="linked-item ${enabled ? '' : 'port-disabled'}">
            <div class="linked-item-head">
                <span class="port-name">${safeHtml(client.name || '客户端规则')}</span>
                <span class="port-protocol">${safeHtml((client.protocol || 'tcp').toUpperCase())}</span>
            </div>
            <div class="linked-meta">所属服务端：${safeHtml(client.server_name || '-')}</div>
            <div class="port-mapping">${mapping}</div>
            <div class="linked-meta">${checkText}</div>
            <div class="linked-actions">
                <button class="btn btn-xs btn-warning" data-linked-action="linked-client-stop" data-server-id="${serverId}" data-port-id="${clientId}"${linkedActionDisabledAttr('linked-client-stop', client.server_id, client.id)}>一键关闭</button>
                <button class="btn btn-xs btn-secondary" data-linked-action="linked-client-check" data-server-id="${serverId}" data-port-id="${clientId}"${linkedActionDisabledAttr('linked-client-check', client.server_id, client.id)}>检查端口</button>
                <button class="btn btn-xs btn-outline" data-linked-action="linked-client-edit" data-server-id="${serverId}" data-port-id="${clientId}"${linkedActionDisabledAttr('linked-client-edit', client.server_id, client.id)}>修改端口</button>
                <button class="btn btn-xs btn-outline" data-linked-action="linked-client-command" data-server-id="${serverId}" data-port-id="${clientId}"${linkedActionDisabledAttr('linked-client-command', client.server_id, client.id)}>链接调用</button>
                <button class="btn btn-xs btn-danger" data-linked-action="linked-client-delete" data-server-id="${serverId}" data-port-id="${clientId}"${linkedActionDisabledAttr('linked-client-delete', client.server_id, client.id)}>删除数据</button>
            </div>
        </div>
    `;
}

function initLinkedActionDelegation() {
    const refreshButton = document.getElementById('linked-refresh-all');
    const serverList = document.getElementById('linked-servers-list');
    const clientList = document.getElementById('linked-clients-list');

    if (refreshButton) {
        refreshButton.addEventListener('click', async () => {
            await loadServers(true);
            showToast('联动状态已刷新', 'success');
            appendLinkedLog('手动刷新联动状态完成', 'success');
        });
    }

    const handler = async (event) => {
        const button = event.target.closest('button[data-linked-action]');
        if (!button) {
            return;
        }

        const action = button.dataset.linkedAction;
        const serverId = button.dataset.serverId;
        const portId = button.dataset.portId;

        if (state.linkedBatchBusy) {
            showToast('批量任务执行中，请稍后再试', 'warning');
            return;
        }

        setLinkedActionButtonBusy(button, true);
        try {
            if (action === 'linked-server-shutdown') {
                if (!window.confirm('确认一键关闭该服务端下所有客户端规则？')) {
                    return;
                }
                const clients = (Array.isArray(state.linkedOverview?.clients) ? state.linkedOverview.clients : [])
                    .filter((item) => String(item.server_id) === String(serverId) && item.enabled !== false);
                if (!clients.length) {
                    showToast('该服务端下没有可关闭的客户端规则', 'warning');
                    appendLinkedLogWithContext({ message: `服务端 ${serverId} 无需关闭（全部已关闭）`, type: 'warning', serverId });
                    return;
                }
                const summary = await runLinkedBatchAction(
                    serverId,
                    clients,
                    '客户端关闭',
                    async (client) => {
                        await apiRequest(`/api/linked/client/${serverId}/${client.id}/shutdown`, { method: 'POST' });
                        return { ok: true, message: '已关闭' };
                    }
                );
                showToast(`客户端关闭完成：成功 ${summary.okCount} / 总数 ${summary.total}`, summary.failedCount ? 'warning' : 'success');
                showLinkedBatchResultModal(serverId, '客户端批量关闭', summary);
                await loadServers(true);
                return;
            }
            if (action === 'linked-server-check') {
                const data = await apiRequest(`/api/linked/server/${serverId}/check`, { method: 'POST' });
                const statusMap = { online: '在线', offline: '离线', pending: '待部署', unknown: '检测中' };
                showToast(`服务端状态：${statusMap[data.status] || '未知'}`, 'success');
                appendLinkedLogWithContext({ message: `服务端 ${serverId} 状态：${statusMap[data.status] || '未知'}`, type: 'success', serverId });
                await loadServers(true);
                return;
            }
            if (action === 'linked-server-check-clients') {
                const clients = (Array.isArray(state.linkedOverview?.clients) ? state.linkedOverview.clients : [])
                    .filter((item) => String(item.server_id) === String(serverId));
                if (!clients.length) {
                    showToast('该服务端暂无客户端规则', 'warning');
                    appendLinkedLogWithContext({ message: `服务端 ${serverId} 无可检测客户端`, type: 'warning', serverId });
                    return;
                }
                const summary = await runLinkedBatchAction(
                    serverId,
                    clients,
                    '客户端检测',
                    async (client) => {
                        const data = await apiRequest(`/api/linked/client/${serverId}/${client.id}/check`, { method: 'POST' });
                        return { ok: Boolean(data.ok), message: String(data.message || '').trim() };
                    }
                );
                showToast(`客户端检测完成：可用 ${summary.okCount} / 总数 ${summary.total}`, summary.failedCount ? 'warning' : 'success');
                showLinkedBatchResultModal(serverId, '客户端批量检测', summary);
                await loadServers(true);
                return;
            }
            if (action === 'linked-server-edit') {
                await editFRPSServer(serverId);
                appendLinkedLogWithContext({ message: `打开服务端 ${serverId} 端口编辑`, type: 'info', serverId });
                return;
            }
            if (action === 'linked-server-delete') {
                if (!window.confirm('确认删除该服务端及其转发规则数据？')) {
                    return;
                }
                await apiRequest(`/api/linked/server/${serverId}/data`, { method: 'DELETE' });
                showToast('服务端数据已删除', 'success');
                appendLinkedLogWithContext({ message: `服务端 ${serverId} 数据已删除`, type: 'warning', serverId });
                await loadServers(true);
                return;
            }
            if (action === 'linked-client-stop') {
                await apiRequest(`/api/linked/client/${serverId}/${portId}/shutdown`, { method: 'POST' });
                showToast('客户端规则已关闭', 'success');
                appendLinkedLogWithContext({ message: `客户端 ${portId} 已关闭`, type: 'success', serverId, portId });
                await loadServers(true);
                return;
            }
            if (action === 'linked-client-check') {
                const data = await apiRequest(`/api/linked/client/${serverId}/${portId}/check`, { method: 'POST' });
                showToast(data.ok ? (data.message || '端口可用') : (data.message || '端口异常'), data.ok ? 'success' : 'warning');
                appendLinkedLogWithContext({ message: `客户端 ${portId} 检测：${data.message || (data.ok ? '可用' : '异常')}`, type: data.ok ? 'success' : 'warning', serverId, portId });
                await loadServers(true);
                return;
            }
            if (action === 'linked-client-edit') {
                openPortModalFromState(serverId, portId);
                appendLinkedLogWithContext({ message: `打开客户端 ${portId} 端口编辑`, type: 'info', serverId, portId });
                return;
            }
            if (action === 'linked-client-command') {
                showSystemSelect(serverId, portId, 'deploy-frpc');
                appendLinkedLogWithContext({ message: `生成客户端 ${portId} 链接调用命令`, type: 'info', serverId, portId });
                return;
            }
            if (action === 'linked-client-delete') {
                if (!window.confirm('确认删除该客户端规则数据？')) {
                    return;
                }
                await apiRequest(`/api/linked/client/${serverId}/${portId}/data`, { method: 'DELETE' });
                showToast('客户端数据已删除', 'success');
                appendLinkedLogWithContext({ message: `客户端 ${portId} 数据已删除`, type: 'warning', serverId, portId });
                await loadServers(true);
            }
        } catch (error) {
            showToast(error.message || '联动操作失败', 'error');
            appendLinkedLogWithContext({ message: `操作失败：${error.message || '未知错误'}`, type: 'error', serverId, portId });
        } finally {
            setLinkedActionButtonBusy(button, false);
        }
    };

    if (serverList) {
        serverList.addEventListener('click', handler);
    }
    if (clientList) {
        clientList.addEventListener('click', handler);
    }
}

function renderServers(servers) {
    const container = document.getElementById('frps-servers-list');
    if (!container) {
        return;
    }

    if (!servers.length) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">🖥️</span>
                <p>暂无服务端</p>
                <p class="hint">点击“添加服务端”开始配置</p>
            </div>
        `;
        return;
    }

    container.innerHTML = servers.map(renderServerCard).join('');
}

function renderServerCard(server) {
    const serverId = safeAttr(server.id);
    let statusText = '检测中';
    let statusClass = 'starting';
    if (server.status === 'online') {
        statusText = '在线';
        statusClass = 'running';
    } else if (server.status === 'pending') {
        statusText = '待部署';
        statusClass = 'starting';
    } else if (server.status === 'offline') {
        statusText = '离线';
        statusClass = 'stopped';
    }
    const serverAddr = String(server.server_addr || '').trim();
    const serverPort = safeHtml(server.server_port);
    const serverAddressText = serverAddr
        ? `${safeHtml(serverAddr)}:${serverPort}`
        : `待部署后自动识别（端口 ${serverPort}）`;
    const ports = Array.isArray(server.ports) ? server.ports : [];

    return `
        <div class="server-card">
            <div class="server-header">
                <div class="server-info">
                    <span class="server-name">${safeHtml(server.name || '服务端')}</span>
                    <span class="server-address">${serverAddressText}</span>
                </div>
                <div class="server-status">
                    <span class="status-dot ${statusClass}"></span>
                    <span>${statusText}</span>
                </div>
            </div>

            <div class="server-ports">
                <div class="ports-header">
                    <h4>转发规则</h4>
                    <button class="btn btn-sm btn-primary" data-action="add-port" data-server-id="${serverId}">➕ 添加规则</button>
                </div>
                <div class="ports-list">
                    ${renderPorts(serverId, ports)}
                </div>
            </div>

            <div class="server-actions">
                <button class="btn btn-sm btn-primary" data-action="generate-frpc" data-server-id="${serverId}">查看客户端配置</button>
                <button class="btn btn-sm btn-secondary" data-action="deploy-frps" data-server-id="${serverId}">安装服务端</button>
                <button class="btn btn-sm btn-outline" data-action="cleanup-frps" data-server-id="${serverId}">清理服务端残留</button>
                <button class="btn btn-sm btn-outline" data-action="refresh-server" data-server-id="${serverId}">刷新状态</button>
                <button class="btn btn-sm btn-outline" data-action="edit-server" data-server-id="${serverId}">编辑</button>
                <button class="btn btn-sm btn-danger" data-action="delete-server" data-server-id="${serverId}">删除</button>
            </div>
        </div>
    `;
}

function renderPorts(serverId, ports) {
    if (!ports.length) {
        return '<p class="no-ports">暂无转发规则</p>';
    }

    return ports.map((port) => {
        const portId = safeAttr(port.id);
        const enabled = port.enabled !== false;
        const protocol = String(port.protocol || '').toLowerCase();
        const checkStatus = formatPortCheckStatus(port);
        const mapping = PORT_PROTOCOLS_WITH_DOMAIN.has(protocol)
            ? `${safeHtml(port.local_ip)}:${safeHtml(port.local_port)} → ${safeHtml(port.domain || '(未配置域名)')}`
            : `${safeHtml(port.local_ip)}:${safeHtml(port.local_port)} → :${safeHtml(port.remote_port)}`;

        return `
            <div class="port-item ${enabled ? '' : 'port-disabled'}">
                <div class="port-info">
                    <span class="port-name">${safeHtml(port.name || '转发规则')}</span>
                    <span class="port-mapping">${mapping}</span>
                    <span class="port-protocol">${safeHtml((port.protocol || 'tcp').toUpperCase())}</span>
                    <span class="port-mapping">${checkStatus}</span>
                </div>
                <div class="port-actions">
                    <button class="btn btn-xs ${enabled ? 'btn-warning' : 'btn-success'}" data-action="toggle-port" data-server-id="${serverId}" data-port-id="${portId}">
                        ${enabled ? '禁用' : '启用'}
                    </button>
                    <button class="btn btn-xs btn-secondary" data-action="check-port" data-server-id="${serverId}" data-port-id="${portId}">检测</button>
                    <button class="btn btn-xs btn-outline" data-action="edit-port" data-server-id="${serverId}" data-port-id="${portId}">编辑</button>
                    <button class="btn btn-xs btn-outline" data-action="deploy-frpc" data-server-id="${serverId}" data-port-id="${portId}">客户端命令</button>
                    <button class="btn btn-xs btn-outline" data-action="cleanup-frpc" data-server-id="${serverId}" data-port-id="${portId}">清理客户端残留</button>
                    <button class="btn btn-xs btn-danger" data-action="delete-port" data-server-id="${serverId}" data-port-id="${portId}">删除</button>
                </div>
            </div>
        `;
    }).join('');
}

function formatPortCheckStatus(port) {
    const checkedAt = String(port?.last_check_at || '').trim();
    if (!checkedAt) {
        return '检测状态：未检测';
    }

    let timeText = checkedAt;
    try {
        const date = new Date(checkedAt);
        if (!Number.isNaN(date.getTime())) {
            timeText = date.toLocaleString('zh-CN', { hour12: false });
        }
    } catch (_error) {
        timeText = checkedAt;
    }

    const ok = Boolean(port?.last_check_ok);
    const msg = String(port?.last_check_message || '').trim();
    const prefix = ok ? '检测状态：可用' : '检测状态：异常';
    if (!msg) {
        return `${prefix}（${timeText}）`;
    }
    return `${prefix}（${timeText}） ${safeHtml(msg)}`;
}

function openFRPSModal(server = null) {
    const form = document.getElementById('frps-form');
    const title = document.getElementById('frps-modal-title');
    const idInput = document.getElementById('frps-server-id');
    if (!form || !title || !idInput) {
        return;
    }

    if (server) {
        title.textContent = '编辑服务端';
        idInput.value = server.id || '';
        form.name.value = server.name || '';
        form.server_port.value = server.server_port || 7000;
        form.manager_url.value = server.manager_url || '';
        form.token.value = server.token || '';
        form.dashboard_port.value = server.dashboard_port || 7500;
        form.vhost_http_port.value = server.vhost_http_port || 80;
        form.vhost_https_port.value = server.vhost_https_port || 443;
        form.lock_https_port.checked = Boolean(server.lock_https_port);
        form.dashboard_user.value = server.dashboard_user || 'admin';
        form.dashboard_pwd.value = server.dashboard_pwd || 'admin';
    } else {
        title.textContent = '添加服务端';
        form.reset();
        idInput.value = '';
        form.manager_url.value = '';
        form.token.value = '';
        form.server_port.value = 7000;
        form.dashboard_port.value = 7500;
        form.vhost_http_port.value = 80;
        form.vhost_https_port.value = 443;
        form.lock_https_port.checked = false;
        form.dashboard_user.value = 'admin';
        form.dashboard_pwd.value = 'admin';
    }

    openModal('frps-modal');
}

function openPortModal(serverId, port = null) {
    const form = document.getElementById('port-form');
    const title = document.getElementById('port-modal-title');
    if (!form || !title) {
        return;
    }

    form.server_id.value = serverId || '';
    if (port) {
        title.textContent = '编辑转发规则';
        form.port_id.value = port.id || '';
        form.name.value = port.name || '';
        form.protocol.value = (port.protocol || 'tcp').toLowerCase();
        form.local_ip.value = port.local_ip || '127.0.0.1';
        form.local_port.value = port.local_port || '';
        form.remote_port.value = port.remote_port || '';
        form.domain.value = port.domain || '';
    } else {
        title.textContent = '添加转发规则';
        form.reset();
        form.port_id.value = '';
        form.server_id.value = serverId || '';
        form.protocol.value = 'tcp';
        form.local_ip.value = '127.0.0.1';
    }

    syncProtocolFields(form.protocol.value);
    openModal('port-modal');
}

function openPortModalFromState(serverId, portId) {
    const server = findServer(serverId);
    if (!server) {
        showToast('服务端不存在', 'error');
        return;
    }
    const port = findPort(server, portId);
    if (!port) {
        showToast('转发规则不存在', 'error');
        return;
    }
    openPortModal(serverId, port);
}

async function saveFRPSServer(event) {
    event.preventDefault();
    const form = document.getElementById('frps-form');
    const serverId = document.getElementById('frps-server-id').value;
    if (!form) {
        return;
    }

    const payload = {
        name: form.name.value.trim(),
        server_port: asInt(form.server_port.value),
        manager_url: form.manager_url.value.trim(),
        dashboard_port: asInt(form.dashboard_port.value),
        dashboard_user: form.dashboard_user.value.trim(),
        dashboard_pwd: form.dashboard_pwd.value,
        vhost_http_port: asInt(form.vhost_http_port.value),
        vhost_https_port: asInt(form.vhost_https_port.value),
        lock_https_port: Boolean(form.lock_https_port.checked),
    };
    const tokenValue = form.token.value.trim();
    if (tokenValue) {
        payload.token = tokenValue;
    }

    try {
        const data = await apiRequest(serverId ? `/api/frps/server/${serverId}` : '/api/frps/server', {
            method: serverId ? 'PUT' : 'POST',
            body: payload,
        });
        showToast(serverId ? '服务端已更新' : '服务端已添加', 'success');
        closeModal('frps-modal');
        await loadServers(false);

        if (!serverId && data.deploy_command) {
            showDeployModal(data.server, data.deploy_command, data.manager_urls, data.deploy_url, data.deploy_urls);
        }
    } catch (error) {
        showToast(error.message || '保存失败', 'error');
    }
}

async function editFRPSServer(serverId) {
    const server = await apiRequest(`/api/frps/server/${serverId}`);
    openFRPSModal(server);
}

async function deleteFRPSServer(serverId) {
    if (!window.confirm('确定要删除这个服务端吗？')) {
        return;
    }
    await apiRequest(`/api/frps/server/${serverId}`, { method: 'DELETE' });
    showToast('服务端已删除', 'success');
    await loadServers(false);
}

async function refreshServer(serverId) {
    const data = await apiRequest(`/api/frps/server/${serverId}/check`, { method: 'POST' });
    const statusTextMap = {
        online: '在线',
        offline: '离线',
        pending: '待部署',
        unknown: '检测中',
    };
    showToast(`服务端状态: ${statusTextMap[data.status] || '未知'}`, 'success');
    await loadServers(true);
}

async function savePortMapping(event) {
    event.preventDefault();
    const form = document.getElementById('port-form');
    if (!form) {
        return;
    }

    const serverId = form.server_id.value;
    const portId = form.port_id.value;
    const protocol = (form.protocol.value || 'tcp').toLowerCase();
    const payload = {
        name: form.name.value.trim(),
        protocol,
        local_ip: form.local_ip.value.trim(),
        local_port: asInt(form.local_port.value),
    };

    if (PORT_PROTOCOLS_WITH_DOMAIN.has(protocol)) {
        payload.domain = form.domain.value.trim();
    } else {
        payload.remote_port = asInt(form.remote_port.value);
        payload.domain = '';
    }

    try {
        await apiRequest(
            portId ? `/api/frps/server/${serverId}/port/${portId}` : `/api/frps/server/${serverId}/port`,
            {
                method: portId ? 'PUT' : 'POST',
                body: payload,
            },
        );
        showToast(portId ? '规则已更新' : '规则已添加', 'success');
        closeModal('port-modal');
        await loadServers(false);
    } catch (error) {
        showToast(error.message || '保存失败', 'error');
    }
}

async function togglePort(serverId, portId) {
    await apiRequest(`/api/frps/server/${serverId}/port/${portId}/toggle`, { method: 'POST' });
    await loadServers(false);
}

async function checkPort(serverId, portId) {
    const server = findServer(serverId);
    const port = server ? findPort(server, portId) : null;
    if (!server || !port) {
        showToast('规则不存在，已刷新列表', 'warning');
        await loadServers(false);
        return;
    }

    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/port/${portId}/check`, { method: 'POST' });
        if (data.ok) {
            showToast(data.message || '检测通过', 'success');
            return;
        }
        showToast(data.message || '检测未通过', 'warning');
    } catch (error) {
        const message = String(error?.message || '').trim();
        if (message.includes('请求的资源不存在')) {
            showToast('当前后端版本不支持“规则检测”，请先执行控制器“安装或更新”后重试', 'warning');
            return;
        }
        showToast(message || '检测失败', 'error');
    }
}

async function deletePort(serverId, portId) {
    if (!window.confirm('确定要删除这条转发规则吗？')) {
        return;
    }
    await apiRequest(`/api/frps/server/${serverId}/port/${portId}`, { method: 'DELETE' });
    showToast('规则已删除', 'success');
    await loadServers(false);
}

async function generateFRPC(serverId) {
    try {
        const securityProfile = getSecurityProfile();
        const data = await apiRequest(
            `/api/frps/server/${serverId}/generate_frpc?security_profile=${encodeURIComponent(securityProfile)}`
        );
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.config || '';
        }
        updateSecurityProfileHint(data.security_profile?.id || securityProfile);
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '生成客户端配置失败', 'error');
    }
}

async function showFRPSDeployCommand(serverId) {
    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/deploy`);
        showDeployModal(data.server, data.command, data.manager_urls, data.deploy_url, data.deploy_urls);
    } catch (error) {
        showToast(error.message || '获取安装命令失败', 'error');
    }
}

async function showFRPSCleanupCommand(serverId) {
    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/cleanup?system=linux`);
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.command || '';
        }
        updateSecurityProfileHint('balanced');
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '获取清理命令失败', 'error');
    }
}

function showDeployModal(server, command, managerUrls = [], deployUrl = '', deployUrls = []) {
    const code = document.querySelector('#deploy-command code');
    if (code) {
        code.textContent = command || '';
    }
    const deployPort = document.getElementById('deploy-port');
    const deployToken = document.getElementById('deploy-token');
    const deployDashboard = document.getElementById('deploy-dashboard');
    const deployUrlElement = document.getElementById('deploy-url');
    const deployUrlsElement = document.getElementById('deploy-urls');
    const deployManagerUrls = document.getElementById('deploy-manager-urls');

    if (deployPort) {
        deployPort.textContent = server?.server_port || '';
    }
    if (deployToken) {
        deployToken.textContent = server?.token || '';
    }
    if (deployDashboard) {
        deployDashboard.textContent = server?.dashboard_port || '';
    }

    const normalizedDeployUrls = Array.isArray(deployUrls)
        ? deployUrls.map((item) => String(item || '').trim()).filter((item) => item)
        : [];
    const primaryDeployUrl = String(deployUrl || normalizedDeployUrls[0] || '').trim();

    if (deployUrlElement) {
        if (primaryDeployUrl) {
            deployUrlElement.textContent = primaryDeployUrl;
            deployUrlElement.href = primaryDeployUrl;
        } else {
            deployUrlElement.textContent = '未生成';
            deployUrlElement.removeAttribute('href');
        }
    }

    if (deployUrlsElement) {
        deployUrlsElement.textContent = normalizedDeployUrls.length ? normalizedDeployUrls.join(' , ') : '未生成';
    }

    if (deployManagerUrls) {
        const urls = Array.isArray(managerUrls) ? managerUrls.filter((item) => String(item || '').trim()) : [];
        deployManagerUrls.textContent = urls.length ? urls.join(' , ') : '未配置';
    }

    openModal('deploy-modal');
    triggerFastStatusSync();
}
function showSystemSelect(serverId, portId, action = 'deploy-frpc') {
    state.selectedDeploy.serverId = serverId;
    state.selectedDeploy.portId = portId;
    state.selectedDeploy.action = action;
    openModal('system-select-modal');
}

function triggerFastStatusSync() {
    loadServers(true);
    setTimeout(() => loadServers(true), 3000);
    setTimeout(() => loadServers(true), 8000);
}

async function selectSystem(system) {
    closeModal('system-select-modal');
    const { serverId, portId, action } = state.selectedDeploy;
    if (!serverId || !portId) {
        showToast('未选择转发规则', 'error');
        return;
    }
    try {
        const securityProfile = getSecurityProfile();
        saveSecurityProfile(securityProfile);
        const query = new URLSearchParams({
            system: String(system || 'linux'),
            security_profile: String(securityProfile || 'balanced'),
        });
        const route = action === 'cleanup-frpc'
            ? `/api/frps/server/${serverId}/port/${portId}/cleanup`
            : `/api/frps/server/${serverId}/port/${portId}/deploy`;
        const data = await apiRequest(
            `${route}?${query.toString()}`
        );
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.command || '';
        }
        if (action === 'cleanup-frpc') {
            updateSecurityProfileHint('balanced');
        } else {
            updateSecurityProfileHint(data.security_profile?.id || securityProfile);
            showToast('命令已生成，执行后可点规则里的“检测”确认是否生效', 'success');
        }
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '生成命令失败', 'error');
    }
}

function syncProtocolFields(protocol) {
    const normalized = String(protocol || '').toLowerCase();
    const domainGroup = document.getElementById('domain-group');
    const domainInput = document.querySelector('#port-form [name="domain"]');
    const remoteInput = document.getElementById('remote-port-input');

    if (!domainGroup || !domainInput || !remoteInput) {
        return;
    }

    const useDomain = PORT_PROTOCOLS_WITH_DOMAIN.has(normalized);
    domainGroup.style.display = useDomain ? 'block' : 'none';
    domainInput.required = useDomain;
    remoteInput.required = !useDomain;
    remoteInput.disabled = useDomain;

    if (useDomain) {
        remoteInput.value = '';
    } else {
        domainInput.value = '';
    }
}

function executeCommand(command) {
    const output = document.getElementById('terminal-output');
    if (!output) {
        return;
    }

    const inputLine = document.createElement('div');
    inputLine.className = 'terminal-line';
    inputLine.textContent = command;
    output.appendChild(inputLine);

    const responseLine = document.createElement('div');
    responseLine.className = 'terminal-line';
    responseLine.style.color = 'var(--text)';
    responseLine.textContent = '已记录命令（本页不直接执行系统命令）';
    output.appendChild(responseLine);

    output.scrollTop = output.scrollHeight;
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

function findServer(serverId) {
    return state.servers.find((server) => String(server.id) === String(serverId)) || null;
}

function findPort(server, portId) {
    const ports = Array.isArray(server?.ports) ? server.ports : [];
    return ports.find((port) => String(port.id) === String(portId)) || null;
}

function asInt(value) {
    if (value === null || value === undefined || value === '') {
        return null;
    }
    const parsed = Number.parseInt(value, 10);
    return Number.isNaN(parsed) ? null : parsed;
}

async function apiRequest(url, options = {}) {
    const fetchOptions = {
        method: options.method || 'GET',
        headers: options.headers ? { ...options.headers } : {},
    };

    if (options.body !== undefined) {
        fetchOptions.headers['Content-Type'] = 'application/json';
        fetchOptions.body = JSON.stringify(options.body);
    }

    const response = await fetch(url, fetchOptions);
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : null;

    if (response.status === 401) {
        window.location.href = '/login';
        throw new Error(payload?.message || '登录已过期，请重新登录');
    }
    if (response.status === 403 && payload?.message?.includes('初始化')) {
        window.location.href = '/setup';
        throw new Error(payload?.message || '请先完成管理员初始化');
    }

    if (!response.ok) {
        const message = payload?.message || `请求失败 (${response.status})`;
        throw new Error(message);
    }

    if (payload && typeof payload === 'object' && !Array.isArray(payload) && payload.success === false) {
        throw new Error(payload.message || '请求失败');
    }

    return payload;
}

async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        return;
    }

    const temp = document.createElement('textarea');
    temp.value = text;
    temp.style.position = 'fixed';
    temp.style.opacity = '0';
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    document.execCommand('copy');
    temp.remove();
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) {
        return;
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = document.createElement('span');
    icon.textContent = type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ';

    const text = document.createElement('span');
    text.textContent = message;

    toast.appendChild(icon);
    toast.appendChild(text);
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function safeHtml(value) {
    const text = String(value === null || value === undefined ? '' : value);
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function safeAttr(value) {
    return safeHtml(value);
}

