const state = {
    localIp: window.location.hostname || '127.0.0.1',
    servers: [],
    agentNodes: [],
    agentRuntimes: [],
    agentJobs: [],
    selectedDeploy: {
        serverId: '',
        portId: '',
    },
    selectedRuntimeIds: new Set(),
    consoleActions: [],
    agentJobFilters: {
        status: '',
        user: '',
        ip: '',
    },
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
    initAgentActionDelegation();
    initTerminal();
    updateSecurityProfileHint(getSecurityProfile());

    await loadAuthMeta();
    await loadLocalIp();
    await loadServers(false);
    await loadAgentData(false);
    setTimeout(() => {
        loadServers(true);
        loadAgentData(true);
    }, 200);
    state.pollTimer = setInterval(() => {
        loadServers(true);
        loadAgentData(true);
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
        });
    });
}

function initModals() {
    bindModalClose('frps-modal', ['close-frps-modal', 'cancel-frps-modal']);
    bindModalClose('port-modal', ['close-port-modal', 'cancel-port-modal']);
    bindModalClose('frpc-modal', ['close-frpc-modal']);
    bindModalClose('system-select-modal', ['close-system-modal']);
    bindModalClose('deploy-modal', ['close-deploy-modal']);
    bindModalClose('agent-node-modal', ['close-agent-node-modal', 'cancel-agent-node-modal']);
    bindModalClose('agent-runtime-modal', ['close-agent-runtime-modal', 'cancel-agent-runtime-modal']);
    bindModalClose('agent-bootstrap-modal', ['close-agent-bootstrap-modal']);
    bindModalClose('console-actions-modal', ['close-console-actions-modal']);
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
    const agentNodeForm = document.getElementById('agent-node-form');
    const agentRuntimeForm = document.getElementById('agent-runtime-form');
    const copyBootstrap = document.getElementById('copy-agent-bootstrap');
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
    if (agentNodeForm) {
        agentNodeForm.addEventListener('submit', saveAgentNode);
    }
    if (agentRuntimeForm) {
        agentRuntimeForm.addEventListener('submit', saveAgentRuntime);
        const templateSelect = agentRuntimeForm.querySelector('select[name="command_template"]');
        const serviceNameInput = agentRuntimeForm.querySelector('input[name="service_name"]');
        if (templateSelect) {
            templateSelect.addEventListener('change', () => applyRuntimeTemplateDefaults(agentRuntimeForm));
        }
        if (serviceNameInput) {
            serviceNameInput.addEventListener('blur', () => applyRuntimeTemplateDefaults(agentRuntimeForm));
        }
    }
    if (copyBootstrap) {
        copyBootstrap.addEventListener('click', async () => {
            const code = document.querySelector('#agent-bootstrap-output code');
            if (!code) {
                return;
            }
            await copyText(code.textContent || '');
            showToast('接入命令已复制', 'success');
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
                showSystemSelect(serverId, portId);
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

function initAgentActionDelegation() {
    const addNodeButton = document.getElementById('add-agent-node');
    const addRuntimeButton = document.getElementById('add-agent-runtime');
    const refreshButton = document.getElementById('refresh-agent-data');
    const batchStartButton = document.getElementById('batch-start-runtimes');
    const batchStopButton = document.getElementById('batch-stop-runtimes');
    const applyFilterButton = document.getElementById('apply-agent-job-filter');
    const clearFilterButton = document.getElementById('clear-agent-job-filter');
    const nodeList = document.getElementById('agent-nodes-list');
    const runtimeList = document.getElementById('agent-runtimes-list');
    const jobsList = document.getElementById('agent-jobs-list');

    if (addNodeButton) {
        addNodeButton.addEventListener('click', () => openModal('agent-node-modal'));
    }
    if (addRuntimeButton) {
        addRuntimeButton.addEventListener('click', () => {
            hydrateAgentNodeSelect();
            openModal('agent-runtime-modal');
        });
    }
    if (refreshButton) {
        refreshButton.addEventListener('click', () => loadAgentData(true));
    }
    if (batchStartButton) {
        batchStartButton.addEventListener('click', () => batchEnsureRuntimes('running'));
    }
    if (batchStopButton) {
        batchStopButton.addEventListener('click', () => batchEnsureRuntimes('stopped'));
    }
    if (applyFilterButton) {
        applyFilterButton.addEventListener('click', () => {
            state.agentJobFilters = readAgentJobFiltersFromForm();
            renderAgentJobs(state.agentJobs);
        });
    }
    if (clearFilterButton) {
        clearFilterButton.addEventListener('click', () => {
            state.agentJobFilters = { status: '', user: '', ip: '' };
            const status = document.getElementById('agent-job-status-filter');
            const user = document.getElementById('agent-job-user-filter');
            const ip = document.getElementById('agent-job-ip-filter');
            if (status) status.value = '';
            if (user) user.value = '';
            if (ip) ip.value = '';
            renderAgentJobs(state.agentJobs);
        });
    }

    if (nodeList) {
        nodeList.addEventListener('click', async (event) => {
            const button = event.target.closest('button[data-agent-action]');
            if (!button) {
                return;
            }
            const action = button.dataset.agentAction;
            const nodeId = button.dataset.nodeId;
            if (!nodeId) {
                return;
            }
            try {
                if (action === 'bootstrap') {
                    await showAgentBootstrap(nodeId);
                    return;
                }
                if (action === 'rotate-token') {
                    await rotateAgentToken(nodeId);
                    return;
                }
                if (action === 'delete-node') {
                    await deleteAgentNode(nodeId);
                }
            } catch (error) {
                showToast(error.message || '节点操作失败', 'error');
            }
        });
    }

    if (runtimeList) {
        runtimeList.addEventListener('change', (event) => {
            const checkbox = event.target.closest('input[data-runtime-id]');
            if (!checkbox) {
                return;
            }
            const runtimeId = checkbox.dataset.runtimeId;
            if (!runtimeId) {
                return;
            }
            if (checkbox.checked) {
                state.selectedRuntimeIds.add(runtimeId);
            } else {
                state.selectedRuntimeIds.delete(runtimeId);
            }
        });

        runtimeList.addEventListener('click', async (event) => {
            const button = event.target.closest('button[data-runtime-action]');
            if (!button) {
                return;
            }
            const action = button.dataset.runtimeAction;
            const runtimeId = button.dataset.runtimeId;
            if (!runtimeId) {
                return;
            }
            try {
                if (action === 'start') {
                    await ensureRuntime(runtimeId, 'running');
                    return;
                }
                if (action === 'stop') {
                    await ensureRuntime(runtimeId, 'stopped');
                    return;
                }
                if (action === 'delete') {
                    await deleteAgentRuntime(runtimeId);
                }
            } catch (error) {
                showToast(error.message || '应用操作失败', 'error');
            }
        });
    }

    if (jobsList) {
        jobsList.addEventListener('click', async (event) => {
            const button = event.target.closest('button[data-job-action]');
            if (!button) {
                return;
            }
            const action = String(button.dataset.jobAction || '').trim();
            const jobId = String(button.dataset.jobId || '').trim();
            if (!jobId) {
                return;
            }
            try {
                if (action === 'retry') {
                    await retryAgentJob(jobId);
                }
            } catch (error) {
                showToast(error.message || '任务操作失败', 'error');
            }
        });
    }
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
    } catch (error) {
        showToast(error.message || '加载服务端失败', 'error');
    }
}

async function loadAgentData(refresh = false) {
    try {
        const [nodes, runtimes, jobs] = await Promise.all([
            apiRequest('/api/agent/nodes'),
            apiRequest('/api/agent/runtimes'),
            apiRequest('/api/agent/jobs'),
        ]);
        state.agentNodes = Array.isArray(nodes) ? nodes : [];
        state.agentRuntimes = Array.isArray(runtimes) ? runtimes : [];
        state.agentJobs = Array.isArray(jobs) ? jobs : [];
        renderAgentNodes(state.agentNodes);
        renderAgentRuntimes(state.agentRuntimes);
        renderAgentJobs(state.agentJobs);
        hydrateAgentNodeSelect();
        populateDeployNodeSelect();
        if (refresh) {
            showToast('节点数据已刷新', 'success');
        }
    } catch (error) {
        showToast(error.message || '加载节点数据失败', 'error');
    }
}

function renderAgentNodes(nodes) {
    const container = document.getElementById('agent-nodes-list');
    if (!container) {
        return;
    }
    if (!nodes.length) {
        container.innerHTML = '<p class="no-ports">暂无节点</p>';
        return;
    }
    container.innerHTML = nodes.map((node) => {
        const nodeId = safeAttr(node.id || '');
        const labels = Array.isArray(node.labels) && node.labels.length ? node.labels.join(', ') : '-';
        const statusText = node.last_seen_at ? '在线(已心跳)' : '离线/未接入';
        return `
            <div class="port-item">
                <div class="port-info">
                    <span class="port-name">${safeHtml(node.name || node.id || '未命名节点')}</span>
                    <span class="port-mapping">ID: ${safeHtml(node.id || '')}</span>
                    <span class="port-protocol">${safeHtml(statusText)}</span>
                    <span class="port-mapping">标签: ${safeHtml(labels)}</span>
                </div>
                <div class="port-actions">
                    <button class="btn btn-xs btn-primary" data-agent-action="bootstrap" data-node-id="${nodeId}">接入命令</button>
                    <button class="btn btn-xs btn-secondary" data-agent-action="rotate-token" data-node-id="${nodeId}">更换密钥</button>
                    <button class="btn btn-xs btn-danger" data-agent-action="delete-node" data-node-id="${nodeId}">删除</button>
                </div>
            </div>
        `;
    }).join('');
}

function renderAgentRuntimes(runtimes) {
    const container = document.getElementById('agent-runtimes-list');
    if (!container) {
        return;
    }
    if (!runtimes.length) {
        container.innerHTML = '<p class="no-ports">暂无应用</p>';
        return;
    }

    const validIds = new Set(runtimes.map((runtime) => String(runtime.id || '')));
    Array.from(state.selectedRuntimeIds).forEach((id) => {
        if (!validIds.has(id)) {
            state.selectedRuntimeIds.delete(id);
        }
    });

    container.innerHTML = runtimes.map((runtime) => {
        const runtimeId = String(runtime.id || '');
        const checked = state.selectedRuntimeIds.has(runtimeId) ? 'checked' : '';
        const nodeName = resolveAgentNodeName(runtime.node_id);
        const metadata = runtime.metadata && typeof runtime.metadata === 'object' ? runtime.metadata : {};
        const templateTag = metadata.command_template ? `模板: ${metadata.command_template} ${metadata.service_name || ''}`.trim() : '';
        const info = templateTag || (metadata.start_command ? `启动命令: ${metadata.start_command}` : '未配置启动命令');
        return `
            <div class="port-item">
                <div class="port-info">
                    <input type="checkbox" data-runtime-id="${safeAttr(runtimeId)}" ${checked}>
                    <span class="port-name">${safeHtml(runtime.name || runtimeId || '未命名应用')}</span>
                    <span class="port-mapping">${safeHtml(runtime.kind || 'frpc').toUpperCase()} | 节点: ${safeHtml(nodeName)}</span>
                    <span class="port-protocol">${safeHtml(runtime.status || 'unknown')}</span>
                    <span class="port-mapping">${safeHtml(info)}</span>
                </div>
                <div class="port-actions">
                    <button class="btn btn-xs btn-success" data-runtime-action="start" data-runtime-id="${safeAttr(runtimeId)}">启动</button>
                    <button class="btn btn-xs btn-warning" data-runtime-action="stop" data-runtime-id="${safeAttr(runtimeId)}">停止</button>
                    <button class="btn btn-xs btn-danger" data-runtime-action="delete" data-runtime-id="${safeAttr(runtimeId)}">删除</button>
                </div>
            </div>
        `;
    }).join('');
}

function readAgentJobFiltersFromForm() {
    const status = document.getElementById('agent-job-status-filter');
    const user = document.getElementById('agent-job-user-filter');
    const ip = document.getElementById('agent-job-ip-filter');
    return {
        status: String(status?.value || '').trim(),
        user: String(user?.value || '').trim().toLowerCase(),
        ip: String(ip?.value || '').trim(),
    };
}

function renderAgentJobs(jobs) {
    const container = document.getElementById('agent-jobs-list');
    if (!container) {
        return;
    }

    const source = Array.isArray(jobs) ? jobs : [];
    const filters = state.agentJobFilters || { status: '', user: '', ip: '' };
    const filtered = source
        .filter((job) => {
            const statusOk = !filters.status || String(job.status || '') === filters.status;
            const userOk = !filters.user || String(job.created_by || '').toLowerCase().includes(filters.user);
            const ipOk = !filters.ip || String(job.created_from_ip || '').includes(filters.ip);
            return statusOk && userOk && ipOk;
        })
        .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))
        .slice(0, 80);

    if (!filtered.length) {
        container.innerHTML = '<p class="no-ports">暂无任务</p>';
        return;
    }

    container.innerHTML = filtered
        .map((job) => {
            const nodeName = resolveAgentNodeName(job.node_id);
            const status = String(job.status || 'unknown');
            const audit = `下发人: ${job.created_by || '-'} | IP: ${job.created_from_ip || '-'} | 来源: ${job.created_via || '-'}`;
            const timeInfo = `创建: ${job.created_at || '-'} | 完成: ${job.finished_at || '-'}`;
            const failedError = status === 'failed' ? String(job.error || '无错误详情') : '';
            const actionHtml = status === 'failed'
                ? `<button class="btn btn-xs btn-warning" data-job-action="retry" data-job-id="${safeAttr(job.id || '')}">重试</button>`
                : '';
            return `
                <div class="port-item">
                    <div class="port-info">
                        <span class="port-name">${safeHtml(job.type || 'unknown')}</span>
                        <span class="port-mapping">节点: ${safeHtml(nodeName)} | 任务ID: ${safeHtml(job.id || '')}</span>
                        <span class="port-protocol">${safeHtml(status)}</span>
                        <span class="port-mapping">${safeHtml(audit)}</span>
                        <span class="port-mapping">${safeHtml(timeInfo)}</span>
                        ${failedError ? `<span class="port-mapping">失败原因: ${safeHtml(failedError)}</span>` : ''}
                    </div>
                    <div class="port-actions">
                        ${actionHtml}
                    </div>
                </div>
            `;
        })
        .join('');
}

async function retryAgentJob(jobId) {
    const data = await apiRequest(`/api/agent/job/${encodeURIComponent(jobId)}/retry`, { method: 'POST' });
    const newJob = data.job || {};
    showToast(`已创建重试任务: ${newJob.id || '-'}`, 'success');
    await loadAgentData(false);
}

function resolveAgentNodeName(nodeId) {
    const target = state.agentNodes.find((item) => String(item.id) === String(nodeId));
    return target ? (target.name || target.id || String(nodeId || '')) : String(nodeId || '-');
}

function hydrateAgentNodeSelect() {
    const select = document.getElementById('agent-runtime-node');
    if (!select) {
        return;
    }
    if (!state.agentNodes.length) {
        select.innerHTML = '<option value="">请先添加节点</option>';
        return;
    }
    select.innerHTML = state.agentNodes
        .map((node) => `<option value="${safeAttr(node.id || '')}">${safeHtml(node.name || node.id || '')}</option>`)
        .join('');
}

async function saveAgentNode(event) {
    event.preventDefault();
    const form = document.getElementById('agent-node-form');
    if (!form) {
        return;
    }
    const labels = String(form.labels.value || '')
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item);
    await apiRequest('/api/agent/node', {
        method: 'POST',
        body: {
            name: form.name.value.trim(),
            labels,
        },
    });
    closeModal('agent-node-modal');
    showToast('节点已创建', 'success');
    await loadAgentData(false);
    form.reset();
}

function applyRuntimeTemplateDefaults(form) {
    const template = String(form.command_template?.value || '').trim();
    const serviceName = String(form.service_name?.value || '').trim();
    if (!template || !serviceName) {
        return;
    }

    if (template === 'systemd') {
        form.start_command.value = `systemctl start ${serviceName}`;
        form.stop_command.value = `systemctl stop ${serviceName}`;
        if (!String(form.check_command.value || '').trim()) {
            form.check_command.value = `systemctl is-active --quiet ${serviceName}`;
        }
        return;
    }

    if (template === 'service') {
        form.start_command.value = `service ${serviceName} start`;
        form.stop_command.value = `service ${serviceName} stop`;
        if (!String(form.check_command.value || '').trim()) {
            form.check_command.value = `service ${serviceName} status`;
        }
    }
}

async function saveAgentRuntime(event) {
    event.preventDefault();
    const form = document.getElementById('agent-runtime-form');
    if (!form) {
        return;
    }
    const commandTemplate = String(form.command_template?.value || '').trim();
    const serviceName = String(form.service_name?.value || '').trim();
    if (commandTemplate && !serviceName) {
        showToast('使用命令模板时，请填写服务名', 'warning');
        return;
    }

    const body = {
        node_id: form.node_id.value,
        id: form.id.value.trim(),
        name: form.name.value.trim(),
        kind: form.kind.value,
        status: form.status.value,
        metadata: {
            command_template: commandTemplate,
            service_name: serviceName,
            start_command: form.start_command.value.trim(),
            stop_command: form.stop_command.value.trim(),
            check_command: form.check_command.value.trim(),
        },
    };
    await apiRequest('/api/agent/runtime', {
        method: 'POST',
        body,
    });
    closeModal('agent-runtime-modal');
    showToast('应用已保存', 'success');
    await loadAgentData(false);
    form.reset();
}

async function deleteAgentNode(nodeId) {
    if (!window.confirm('删除节点将同时清理该节点的任务与应用，确认继续？')) {
        return;
    }
    await apiRequest(`/api/agent/node/${encodeURIComponent(nodeId)}`, { method: 'DELETE' });
    showToast('节点已删除', 'success');
    await loadAgentData(false);
}

async function deleteAgentRuntime(runtimeId) {
    if (!window.confirm('确认删除该应用？删除后将无法在面板中直接开关。')) {
        return;
    }
    await apiRequest(`/api/agent/runtime/${encodeURIComponent(runtimeId)}`, { method: 'DELETE' });
    state.selectedRuntimeIds.delete(String(runtimeId || ''));
    showToast('应用已删除', 'success');
    await loadAgentData(false);
}

async function rotateAgentToken(nodeId) {
    const data = await apiRequest(`/api/agent/node/${encodeURIComponent(nodeId)}/rotate-token`, { method: 'POST' });
    const token = data.agent_token || '';
    if (token) {
        await copyText(token);
        showToast('密钥已更换并复制到剪贴板', 'success');
    } else {
        showToast('密钥已更换', 'success');
    }
}

async function showAgentBootstrap(nodeId) {
    const data = await apiRequest(`/api/agent/node/${encodeURIComponent(nodeId)}/bootstrap`, { method: 'POST' });
    const code = document.querySelector('#agent-bootstrap-output code');
    if (code) {
        code.textContent = data.command || '';
    }
    openModal('agent-bootstrap-modal');
    await loadAgentData(false);
}

async function ensureRuntime(runtimeId, desiredState) {
    const route = desiredState === 'running' ? 'ensure-running' : 'ensure-stopped';
    await apiRequest(`/api/agent/runtime/${encodeURIComponent(runtimeId)}/${route}`, { method: 'POST' });
    showToast(desiredState === 'running' ? '已下发启动任务' : '已下发停止任务', 'success');
}

async function batchEnsureRuntimes(desiredState) {
    const ids = Array.from(state.selectedRuntimeIds);
    if (!ids.length) {
        showToast('请先勾选应用', 'warning');
        return;
    }
    const route = desiredState === 'running' ? 'ensure-running' : 'ensure-stopped';
    await Promise.all(
        ids.map((runtimeId) => apiRequest(`/api/agent/runtime/${encodeURIComponent(runtimeId)}/${route}`, { method: 'POST' }))
    );
    showToast(`已批量下发${desiredState === 'running' ? '启动' : '停止'}任务`, 'success');
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
        const mapping = PORT_PROTOCOLS_WITH_DOMAIN.has(protocol)
            ? `${safeHtml(port.local_ip)}:${safeHtml(port.local_port)} → ${safeHtml(port.domain || '(未配置域名)')}`
            : `${safeHtml(port.local_ip)}:${safeHtml(port.local_port)} → :${safeHtml(port.remote_port)}`;

        return `
            <div class="port-item ${enabled ? '' : 'port-disabled'}">
                <div class="port-info">
                    <span class="port-name">${safeHtml(port.name || '转发规则')}</span>
                    <span class="port-mapping">${mapping}</span>
                    <span class="port-protocol">${safeHtml((port.protocol || 'tcp').toUpperCase())}</span>
                </div>
                <div class="port-actions">
                    <button class="btn btn-xs ${enabled ? 'btn-warning' : 'btn-success'}" data-action="toggle-port" data-server-id="${serverId}" data-port-id="${portId}">
                        ${enabled ? '禁用' : '启用'}
                    </button>
                    <button class="btn btn-xs btn-outline" data-action="edit-port" data-server-id="${serverId}" data-port-id="${portId}">编辑</button>
                    <button class="btn btn-xs btn-outline" data-action="deploy-frpc" data-server-id="${serverId}" data-port-id="${portId}">客户端命令</button>
                    <button class="btn btn-xs btn-danger" data-action="delete-port" data-server-id="${serverId}" data-port-id="${portId}">删除</button>
                </div>
            </div>
        `;
    }).join('');
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
function showSystemSelect(serverId, portId) {
    state.selectedDeploy.serverId = serverId;
    state.selectedDeploy.portId = portId;
    populateDeployNodeSelect();
    openModal('system-select-modal');
}

function populateDeployNodeSelect() {
    const select = document.getElementById('deploy-link-node-select');
    if (!select) {
        return;
    }
    const current = String(select.value || '').trim();
    const options = ['<option value="">不绑定节点（仅生成部署命令）</option>'];
    state.agentNodes.forEach((node) => {
        const nodeId = String(node?.id || '').trim();
        if (!nodeId) {
            return;
        }
        const nodeName = String(node?.name || nodeId).trim();
        options.push(`<option value="${safeAttr(nodeId)}">${safeHtml(nodeName)} (${safeHtml(nodeId)})</option>`);
    });
    select.innerHTML = options.join('');
    if (current && state.agentNodes.some((node) => String(node?.id || '').trim() === current)) {
        select.value = current;
    }
}

function getDeployLinkedNodeId() {
    const select = document.getElementById('deploy-link-node-select');
    if (!select) {
        return '';
    }
    return String(select.value || '').trim();
}

function triggerFastStatusSync() {
    loadServers(true);
    setTimeout(() => loadServers(true), 3000);
    setTimeout(() => loadServers(true), 8000);
}

async function selectSystem(system) {
    closeModal('system-select-modal');
    const { serverId, portId } = state.selectedDeploy;
    if (!serverId || !portId) {
        showToast('未选择转发规则', 'error');
        return;
    }
    try {
        const securityProfile = getSecurityProfile();
        const linkedNodeId = getDeployLinkedNodeId();
        saveSecurityProfile(securityProfile);
        const query = new URLSearchParams({
            system: String(system || 'linux'),
            security_profile: String(securityProfile || 'balanced'),
        });
        if (linkedNodeId) {
            query.set('node_id', linkedNodeId);
        }
        const data = await apiRequest(
            `/api/frps/server/${serverId}/port/${portId}/deploy?${query.toString()}`
        );
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.command || '';
        }
        updateSecurityProfileHint(data.security_profile?.id || securityProfile);
        if (data.linked_runtime?.id) {
            showToast('已绑定节点并创建可控客户端应用，可在“节点与应用”中开关/删除', 'success');
            await loadAgentData(false);
        }
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '生成客户端命令失败', 'error');
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

