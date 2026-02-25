const state = {
    localIp: window.location.hostname || '127.0.0.1',
    servers: [],
    selectedDeploy: {
        serverId: '',
        portId: '',
    },
    pollTimer: null,
};

const PORT_PROTOCOLS_WITH_DOMAIN = new Set(['http', 'https']);

document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initModals();
    initForms();
    initServerActionDelegation();
    initTerminal();

    await loadLocalIp();
    await loadServers(false);
    setTimeout(() => {
        loadServers(true);
    }, 200);
    state.pollTimer = setInterval(() => loadServers(true), 10000);
});

function initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    const panels = document.querySelectorAll('.tab-panel');
    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach((item) => item.classList.remove('active'));
            panels.forEach((item) => item.classList.remove('active'));

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

    document.querySelectorAll('.system-btn[data-system]').forEach((button) => {
        button.addEventListener('click', () => selectSystem(button.dataset.system));
    });
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

function clearTerminalOutput() {
    const output = document.getElementById('terminal-output');
    if (!output) {
        return;
    }
    output.innerHTML = `
        <div class="terminal-line">FRP 管理面板终端 v1.0</div>
        <div class="terminal-line">请在下方输入命令...</div>
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
        showToast(error.message || '加载服务器失败', 'error');
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
                <p>暂无 FRPS 服务器</p>
                <p class="hint">点击“添加服务器”登记一个新的 FRPS 服务器</p>
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
    } else if (server.status === 'offline') {
        statusText = '离线';
        statusClass = 'stopped';
    }
    const ports = Array.isArray(server.ports) ? server.ports : [];

    return `
        <div class="server-card">
            <div class="server-header">
                <div class="server-info">
                    <span class="server-name">${safeHtml(server.name || 'FRPS服务器')}</span>
                    <span class="server-address">${safeHtml(server.server_addr)}:${safeHtml(server.server_port)}</span>
                </div>
                <div class="server-status">
                    <span class="status-dot ${statusClass}"></span>
                    <span>${statusText}</span>
                </div>
            </div>

            <div class="server-ports">
                <div class="ports-header">
                    <h4>端口映射</h4>
                    <button class="btn btn-sm btn-primary" data-action="add-port" data-server-id="${serverId}">➕ 添加映射</button>
                </div>
                <div class="ports-list">
                    ${renderPorts(serverId, ports)}
                </div>
            </div>

            <div class="server-actions">
                <button class="btn btn-sm btn-primary" data-action="generate-frpc" data-server-id="${serverId}">生成 FRPC 配置</button>
                <button class="btn btn-sm btn-secondary" data-action="deploy-frps" data-server-id="${serverId}">一键部署 FRPS</button>
                <button class="btn btn-sm btn-outline" data-action="refresh-server" data-server-id="${serverId}">刷新状态</button>
                <button class="btn btn-sm btn-outline" data-action="edit-server" data-server-id="${serverId}">编辑</button>
                <button class="btn btn-sm btn-danger" data-action="delete-server" data-server-id="${serverId}">删除</button>
            </div>
        </div>
    `;
}

function renderPorts(serverId, ports) {
    if (!ports.length) {
        return '<p class="no-ports">暂无端口映射</p>';
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
                    <span class="port-name">${safeHtml(port.name || '端口映射')}</span>
                    <span class="port-mapping">${mapping}</span>
                    <span class="port-protocol">${safeHtml((port.protocol || 'tcp').toUpperCase())}</span>
                </div>
                <div class="port-actions">
                    <button class="btn btn-xs ${enabled ? 'btn-warning' : 'btn-success'}" data-action="toggle-port" data-server-id="${serverId}" data-port-id="${portId}">
                        ${enabled ? '禁用' : '启用'}
                    </button>
                    <button class="btn btn-xs btn-outline" data-action="edit-port" data-server-id="${serverId}" data-port-id="${portId}">编辑</button>
                    <button class="btn btn-xs btn-outline" data-action="deploy-frpc" data-server-id="${serverId}" data-port-id="${portId}">一键部署</button>
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
        title.textContent = '编辑 FRPS 服务器';
        idInput.value = server.id || '';
        form.name.value = server.name || '';
        form.server_addr.value = server.server_addr || state.localIp;
        form.server_port.value = server.server_port || 7000;
        form.token.value = server.token || '';
        form.dashboard_port.value = server.dashboard_port || 7500;
        form.vhost_http_port.value = server.vhost_http_port || 80;
        form.vhost_https_port.value = server.vhost_https_port || 443;
        form.dashboard_user.value = server.dashboard_user || 'admin';
        form.dashboard_pwd.value = server.dashboard_pwd || 'admin';
    } else {
        title.textContent = '添加 FRPS 服务器';
        form.reset();
        idInput.value = '';
        form.server_addr.value = state.localIp;
        form.token.value = generateToken();
        form.server_port.value = 7000;
        form.dashboard_port.value = 7500;
        form.vhost_http_port.value = 80;
        form.vhost_https_port.value = 443;
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
        title.textContent = '编辑端口映射';
        form.port_id.value = port.id || '';
        form.name.value = port.name || '';
        form.protocol.value = (port.protocol || 'tcp').toLowerCase();
        form.local_ip.value = port.local_ip || '127.0.0.1';
        form.local_port.value = port.local_port || '';
        form.remote_port.value = port.remote_port || '';
        form.domain.value = port.domain || '';
    } else {
        title.textContent = '添加端口映射';
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
        showToast('服务器不存在', 'error');
        return;
    }
    const port = findPort(server, portId);
    if (!port) {
        showToast('端口映射不存在', 'error');
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
        server_addr: form.server_addr.value.trim(),
        server_port: asInt(form.server_port.value),
        token: form.token.value.trim(),
        dashboard_port: asInt(form.dashboard_port.value),
        dashboard_user: form.dashboard_user.value.trim(),
        dashboard_pwd: form.dashboard_pwd.value,
        vhost_http_port: asInt(form.vhost_http_port.value),
        vhost_https_port: asInt(form.vhost_https_port.value),
    };

    try {
        const data = await apiRequest(serverId ? `/api/frps/server/${serverId}` : '/api/frps/server', {
            method: serverId ? 'PUT' : 'POST',
            body: payload,
        });
        showToast(serverId ? '服务器已更新' : '服务器已添加', 'success');
        closeModal('frps-modal');
        await loadServers(false);

        if (!serverId && data.deploy_command) {
            showDeployModal(data.server, data.deploy_command);
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
    if (!window.confirm('确定要删除此服务器吗？')) {
        return;
    }
    await apiRequest(`/api/frps/server/${serverId}`, { method: 'DELETE' });
    showToast('服务器已删除', 'success');
    await loadServers(false);
}

async function refreshServer(serverId) {
    const data = await apiRequest(`/api/frps/server/${serverId}/check`, { method: 'POST' });
    showToast(`服务器状态: ${data.status === 'online' ? '在线' : '离线'}`, 'success');
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
        showToast(portId ? '映射已更新' : '映射已添加', 'success');
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
    if (!window.confirm('确定要删除此端口映射吗？')) {
        return;
    }
    await apiRequest(`/api/frps/server/${serverId}/port/${portId}`, { method: 'DELETE' });
    showToast('映射已删除', 'success');
    await loadServers(false);
}

async function generateFRPC(serverId) {
    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/generate_frpc`);
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.config || '';
        }
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '生成配置失败', 'error');
    }
}

async function showFRPSDeployCommand(serverId) {
    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/deploy`);
        showDeployModal(data.server, data.command);
    } catch (error) {
        showToast(error.message || '获取部署命令失败', 'error');
    }
}

function showDeployModal(server, command) {
    const code = document.querySelector('#deploy-command code');
    if (code) {
        code.textContent = command || '';
    }
    const deployPort = document.getElementById('deploy-port');
    const deployToken = document.getElementById('deploy-token');
    const deployDashboard = document.getElementById('deploy-dashboard');
    if (deployPort) {
        deployPort.textContent = server?.server_port || '';
    }
    if (deployToken) {
        deployToken.textContent = server?.token || '';
    }
    if (deployDashboard) {
        deployDashboard.textContent = server?.dashboard_port || '';
    }
    openModal('deploy-modal');
    triggerFastStatusSync();
}

function showSystemSelect(serverId, portId) {
    state.selectedDeploy.serverId = serverId;
    state.selectedDeploy.portId = portId;
    openModal('system-select-modal');
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
        showToast('未选择端口映射', 'error');
        return;
    }
    try {
        const data = await apiRequest(`/api/frps/server/${serverId}/port/${portId}/deploy?system=${encodeURIComponent(system)}`);
        const code = document.querySelector('#frpc-config-output code');
        if (code) {
            code.textContent = data.command || '';
        }
        openModal('frpc-modal');
    } catch (error) {
        showToast(error.message || '生成部署命令失败', 'error');
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
    responseLine.textContent = '命令已执行（演示模式）';
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

function generateToken(length = 32) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let token = '';
    for (let i = 0; i < length; i += 1) {
        token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
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
