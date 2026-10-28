'use strict';
'require view';
'require fs';
'require ui';

/*
 * LuCI「线路体检」页（0.3.0）
 *
 * 数据来自一次 `isp-split linecheck --json`（可选 --force）：
 *   · 服务端已按 LINE_CHECK_MIN_INTERVAL 做结果缓存，60s 内重复调用不会
 *     再打 STUN/CDN；本页只负责把缓存状态和倒计时显示清楚。
 *   · 页面不轮询、不自动重测：体检会访问第三方归属地服务并产生真实流量，
 *     必须由用户点「立即体检」触发。
 *   · 所有展示字段都来自 JSON，前端不猜 NAT 类型、不算分；评分规则与硬上限
 *     在 shell 侧唯一实现，避免两套口径。
 */

var CMD = '/usr/sbin/isp-split';

var ICONS = {
	refresh: '<path d="M20 11a8 8 0 1 0-2.3 6.3"/><path d="M20 4v7h-7"/>',
	pulse: '<path d="M2 12h4l2.5-6 3.5 12 2.5-6H22"/>',
	chevron: '<path d="M6 9l6 6 6-6"/>',
	shield: '<path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z"/>'
};

function svgIcon(name, size) {
	var span = document.createElement('span');
	span.className = 'isp-ico';
	span.innerHTML = '<svg viewBox="0 0 24 24" width="' + (size || 16) + '" height="' + (size || 16) +
		'" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" ' +
		'stroke-linejoin="round" aria-hidden="true">' + (ICONS[name] || ICONS.pulse) + '</svg>';
	return span;
}

function parseJson(res) {
	try {
		return JSON.parse(((res && res.stdout) || '').trim() || 'null');
	} catch (e) {
		return null;
	}
}

function execJson(args) {
	return fs.exec(CMD, args).then(function(res) {
		var data = parseJson(res);
		if (res && res.code && !data) {
			var out = ((res.stdout || '') + (res.stderr || '')).trim();
			throw new Error(out || ('isp-split ' + args.join(' ') + ' 退出码 ' + res.code));
		}
		if (!data)
			throw new Error('isp-split ' + args.join(' ') + ' 没有返回可解析的 JSON');
		return data;
	});
}

function fmtMs(v) {
	if (v === null || v === undefined || v === '' || v === 0)
		return '—';
	return v + 'ms';
}

function fmtNum(v) {
	return (v === null || v === undefined) ? '—' : String(v);
}

function gradeClass(g) {
	return 'lc-grade is-' + String(g || 'd').toLowerCase();
}

function natClass(type) {
	if (type === 'public' || type === 'cone')
		return 'is-ok';
	if (type === 'symmetric')
		return 'is-warn';
	if (type === 'cgnat')
		return 'is-bad';
	return 'is-muted';
}

function stateText(state) {
	if (state === 'online')
		return _('在线');
	if (state === 'offline')
		return _('离线');
	return _('未知');
}

function classText(c) {
	if (c === 'public')
		return _('公网');
	if (c === 'cgnat')
		return _('CGNAT');
	if (c === 'private')
		return _('私网');
	return _('无地址');
}

function geoText(geo) {
	if (!geo || geo.status === 'off')
		return _('未查询（隐私开关关闭）');
	if (geo.status === 'noip')
		return _('无公网出口 IP，跳过');
	if (geo.status === 'ok')
		return (geo.location || '') + (geo.provider ? '（' + geo.provider + '）' : '');
	return _('查询失败（不影响评分）');
}

function targetText(t) {
	if (!t)
		return _('无可用目标');
	return t.domain + ' → ' + t.ip + ' · ' + (t.label || t.isp || '?') +
		' · ' + (t.mode === 'same_isp' ? _('同运营商') : _('跨网基线'));
}

function text(tag, cls, value) {
	return E(tag, { 'class': cls }, [ value ]);
}

/* 一行 key/value；value 可以是字符串或 DOM 节点 */
function row(label, value) {
	return E('div', { 'class': 'lc-row' }, [
		E('span', { 'class': 'lc-key' }, [ label ]),
		E('span', { 'class': 'lc-val' }, [ value ])
	]);
}

function seg(label, value) {
	return E('div', { 'class': 'lc-seg' }, [
		E('span', { 'class': 'lc-seg-label' }, [ label ]),
		E('span', { 'class': 'lc-seg-value' }, [ value ])
	]);
}

return view.extend({
	load: function() {
		return fs.exec(CMD, ['linecheck', '--json']).then(function(res) {
			return { res: res, data: parseJson(res) };
		}).catch(function(err) {
			return { res: null, data: null, error: String(err) };
		});
	},

	render: function(loaded) {
		var self = this;
		this.data = loaded && loaded.data;
		this.loadError = loaded && loaded.error;
		this.nextAt = 0;
		this.busy = false;

		var cards = E('div', { 'id': 'lc-cards', 'class': 'isp-cards lc-cards' });
		var meta = E('div', { 'id': 'lc-meta', 'class': 'lc-meta' });
		var msg = E('div', { 'id': 'lc-msg', 'class': 'lc-msg' });
		this.cardsBox = cards;
		this.metaBox = meta;
		this.msgBox = msg;

		var runBtn = E('button', {
			'class': 'cbi-button cbi-button-action lc-run',
			'click': function() { self.run(true); }
		}, [ svgIcon('pulse'), E('span', {}, [ _('立即体检') ]) ]);
		this.runBtn = runBtn;

		var pill = E('span', { 'id': 'lc-pill', 'class': 'isp-pill' });
		this.pill = pill;

		this.paint();

		/* 倒计时：只更新按钮文字，不触发任何请求 */
		if (this._timer)
			clearInterval(this._timer);
		this._timer = setInterval(function() {
			if (!self.runBtn || !self.runBtn.parentNode) {
				clearInterval(self._timer);
				return;
			}
			self.paintButton();
		}, 1000);

		return E('div', { 'class': 'isp-app cbi-map' }, [
			E('link', { 'rel': 'stylesheet', 'href': L.resource('isp-split/isp-split.css') }),

			E('div', { 'class': 'isp-hero' }, [
				E('h2', {}, [ _('线路体检') ]),
				E('div', { 'class': 'isp-sub' }, [
					_('逐条 WAN 检查出口类型、四段延迟、NAT 与归属地。只读探测，不改 mwan3/nft 规则；60 秒内重复执行直接返回缓存。')
				]),
				E('div', { 'class': 'isp-toolbar' }, [ runBtn, pill ])
			]),

			E('div', { 'class': 'lc-privacy' }, [
				svgIcon('shield', 15),
				E('span', {}, [
					_('归属地查询只发送每条线的出口公网 IP，不发送内网地址、设备名、MAC 或流量内容；可在「配置 → 线路体检」关闭。')
				])
			]),

			meta,
			msg,
			cards
		]);
	},

	/* ---------------- 运行 ---------------- */

	run: function(force) {
		var self = this;
		if (this.busy)
			return;
		var now = Math.floor(Date.now() / 1000);
		if (force && this.nextAt && now < this.nextAt) {
			ui.addNotification(null, E('p', {}, [
				_('体检结果仍在缓存有效期内（还需 ') + (this.nextAt - now) + _(' 秒）。') +
				_('服务端会直接返回缓存；如需强制重测请用命令行 --force。')
			]), 'info');
			return;
		}

		this.busy = true;
		this.paintButton();
		this.setMsg(_('正在体检：依次检查每条 WAN，通常 3-10 秒，线路差时最多约 20 秒…'), 'info');

		var args = ['linecheck', '--json'];
		if (force)
			args.push('--force');

		execJson(args).then(function(data) {
			self.data = data;
			self.loadError = null;
			self.nextAt = (+data.generated || now) + (+data.interval || 60);
			self.busy = false;
			self.paint();
			self.setMsg(_('体检完成。'), 'ok');
		}).catch(function(err) {
			self.busy = false;
			self.paintButton();
			self.setMsg(_('体检失败：') + String(err), 'bad');
			ui.addNotification(null, E('p', {}, [ _('体检失败：') + String(err) ]), 'danger');
		});
	},

	setMsg: function(t, kind) {
		if (!this.msgBox)
			return;
		this.msgBox.textContent = t || '';
		this.msgBox.className = 'lc-msg' + (kind ? ' is-' + kind : '');
	},

	paintButton: function() {
		if (!this.runBtn)
			return;
		var now = Math.floor(Date.now() / 1000);
		var left = this.nextAt ? Math.max(0, this.nextAt - now) : 0;
		var span = this.runBtn.querySelector('span:last-child');
		if (this.busy) {
			this.runBtn.disabled = true;
			if (span) span.textContent = _('体检中…');
		} else if (left > 0) {
			this.runBtn.disabled = true;
			if (span) span.textContent = _('立即体检（') + left + _('s）');
		} else {
			this.runBtn.disabled = false;
			if (span) span.textContent = _('立即体检');
		}
		if (this.pill) {
			this.pill.className = 'isp-pill' + (this.busy ? ' is-busy' : '');
			this.pill.textContent = this.busy
				? _('刷新中…')
				: (this.data && this.data.cached
					? _('缓存 · ') + (this.data.age || 0) + _(' 秒前')
					: _('实时结果'));
		}
	},

	/* ---------------- 渲染 ---------------- */

	paint: function() {
		if (!this.cardsBox)
			return;
		while (this.cardsBox.firstChild)
			this.cardsBox.removeChild(this.cardsBox.firstChild);
		while (this.metaBox.firstChild)
			this.metaBox.removeChild(this.metaBox.firstChild);

		this.paintButton();

		if (this.loadError) {
			this.cardsBox.appendChild(E('div', { 'class': 'isp-empty' }, [
				_('读取线路体检失败：') + this.loadError
			]));
			return;
		}
		if (!this.data) {
			this.cardsBox.appendChild(E('div', { 'class': 'isp-empty' }, [
				_('没有拿到体检结果。检查 isp-split 是否已安装、服务是否正常。')
			]));
			return;
		}

		var d = this.data;
		if (!this.nextAt)
			this.nextAt = (+d.generated || Math.floor(Date.now() / 1000)) + (+d.interval || 60);

		var bits = [];
		bits.push(_('版本 ') + (d.version || '?'));
		if (d.generated)
			bits.push(_('生成于 ') + new Date(+d.generated * 1000).toLocaleString());
		if (d.cached)
			bits.push(_('缓存结果 · ') + (d.age || 0) + _(' 秒前'));
		else
			bits.push(_('实时结果'));
		bits.push(_('缓存间隔 ') + (d.interval || 60) + 's');
		bits.push(d.socat ? _('socat 可用') : _('socat 未安装（NAT 只能判未知）'));
		bits.push(d.geo_enabled ? _('归属地查询开') : _('归属地查询关'));
		this.metaBox.textContent = bits.join(' · ');

		var wans = d.wans || [];
		if (!wans.length) {
			this.cardsBox.appendChild(E('div', { 'class': 'isp-empty' }, [
				(d.errors && d.errors.length)
					? d.errors.join('；')
					: _('没有可体检的 WAN。先在 mwan3 启用接口，或在命令行用 --wan 指定。')
			]));
			return;
		}

		for (var i = 0; i < wans.length; i++)
			this.cardsBox.appendChild(this.card(wans[i], d));
	},

	card: function(w, d) {
		var self = this;
		var sc = w.score || {};
		var nat = w.nat || {};
		var lat = w.latency || {};
		var geo = w.geo || {};
		var http = w.http || {};
		var detail = E('div', { 'class': 'lc-detail', 'hidden': '' });

		var toggle = E('button', {
			'class': 'lc-toggle',
			'click': function() {
				if (detail.hasAttribute('hidden')) {
					detail.removeAttribute('hidden');
					toggle.classList.add('is-open');
					toggle.lastChild.textContent = _('收起明细');
				} else {
					detail.setAttribute('hidden', '');
					toggle.classList.remove('is-open');
					toggle.lastChild.textContent = _('查看明细');
				}
			}
		}, [ svgIcon('chevron', 14), E('span', {}, [ _('查看明细') ]) ]);

		var multi = w.multi_nat
			? E('span', { 'class': 'lc-tag is-warn' }, [ _('多层 NAT/代理') ])
			: null;

		var natTag = E('span', { 'class': 'lc-tag ' + natClass(nat.type) }, [ nat.label || _('未知') ]);

		var card = E('article', {
			'class': 'isp-card lc-card',
			'style': '--lc-accent: ' + (sc.grade === 'A' ? 'var(--isp-ok)' :
				sc.grade === 'B' ? 'var(--isp-primary)' :
				sc.grade === 'C' ? 'var(--isp-warn)' : 'var(--isp-bad)')
		}, [
			E('div', { 'class': 'lc-head' }, [
				E('div', { 'class': 'lc-title' }, [
					E('span', { 'class': 'lc-name' }, [ w.iface || '?' ]),
					E('span', { 'class': 'lc-dev' }, [ w.device || '' ]),
					E('span', { 'class': 'lc-state ' + (w.up ? 'is-on' : 'is-off') }, [
						stateText(w.state)
					])
				]),
				E('div', { 'class': 'lc-score' }, [
					E('span', { 'class': gradeClass(sc.grade) }, [ sc.grade || 'D' ]),
					E('span', { 'class': 'lc-total' }, [ fmtNum(sc.total) ]),
					E('span', { 'class': 'lc-max' }, [ '/100' ])
				])
			]),

			E('div', { 'class': 'lc-kv' }, [
				row(_('WAN IP'), [
					E('span', {}, [ w.wan_ip || '—' ]),
					E('span', { 'class': 'lc-tag is-muted' }, [ classText(w.ip_class) ])
				]),
				row(_('出口 IP'), [
					E('span', {}, [ w.exit_ip || _('未取到（可能未真正出网）') ]),
					multi
				]),
				row(_('运营商'), [ w.isp_label || _('未知') ]),
				row(_('NAT 类型'), [ natTag,
					E('span', { 'class': 'lc-sub' }, [
						nat.confidence === 'high' ? _('置信度高')
							: nat.confidence === 'medium' ? _('置信度中（仅一个探测点）')
							: _('置信度未知')
					])
				]),
				row(_('归属地'), [ geoText(geo) ])
			]),

			E('div', { 'class': 'lc-segs' }, [
				seg('DNS', fmtMs(lat.dns_ms)),
				seg('TCP', fmtMs(lat.tcp_ms)),
				seg('TLS', fmtMs(lat.tls_ms)),
				seg(_('首字节'), fmtMs(lat.ttfb_ms))
			]),

			E('div', { 'class': 'lc-line2' }, [
				E('span', {}, [ _('抖动 ') + fmtNum(lat.jitter_ms) + 'ms' ]),
				E('span', {}, [ _('丢包 ') + fmtNum(lat.loss_pct) + '%' ]),
				E('span', {}, [ _('HTTP ') + fmtNum(http.code) ]),
				E('span', {}, [ _('目标：') + targetText(w.target) ])
			]),

			E('div', { 'class': 'lc-advice' + (sc.grade === 'D' || nat.type === 'cgnat' ? ' is-bad' : '') }, [
				svgIcon('pulse', 15),
				E('span', {}, [ sc.advice || _('无建议') ])
			]),

			toggle,
			detail
		]);

		/* 明细：评分拆分 + 硬上限 + STUN 探测 + 原始目标/延迟 */
		var tbody = E('tbody', {});
		(sc.breakdown || []).forEach(function(b) {
			tbody.appendChild(E('tr', {}, [
				E('td', { 'data-th': _('项目') }, [ b.label || b.key ]),
				E('td', { 'data-th': _('观测') }, [ b.value || '—' ]),
				E('td', { 'data-th': _('得分') }, [ (b.points || 0) + ' / ' + (b.max || 0) ]),
				E('td', { 'data-th': _('依据') }, [ b.reason || '—' ])
			]));
		});

		detail.appendChild(E('h4', {}, [ _('评分明细') ]));
		detail.appendChild(E('table', { 'class': 'lc-table' }, [
			E('thead', {}, [ E('tr', {}, [
				E('th', {}, [_('项目')]), E('th', {}, [_('观测')]),
				E('th', {}, [_('得分')]), E('th', {}, [_('依据')])
			]) ]),
			tbody
		]));

		if (sc.caps && sc.caps.length) {
			var ul = E('ul', { 'class': 'lc-caps' });
			sc.caps.forEach(function(c) { ul.appendChild(E('li', {}, [ c ])); });
			detail.appendChild(E('h4', {}, [ _('硬上限') ]));
			detail.appendChild(ul);
		}

		var probes = nat.probes || [];
		if (probes.length) {
			var pt = E('tbody', {});
			probes.forEach(function(p) {
				pt.appendChild(E('tr', {}, [
					E('td', { 'data-th': _('服务器') }, [ p.server || '—' ]),
					E('td', { 'data-th': 'IP' }, [ p.ip || '—' ]),
					E('td', { 'data-th': _('状态') }, [ p.status === 'ok' ? _('成功') : p.status === 'bad' ? _('坏包') : _('超时') ]),
					E('td', { 'data-th': _('映射') }, [ p.mapped || '—' ]),
					E('td', { 'data-th': 'RTT' }, [ p.rtt_ms ? p.rtt_ms + 'ms' : '—' ])
				]));
			});
			detail.appendChild(E('h4', {}, [ _('STUN 探测') + (nat.detail ? '：' + nat.detail : '') ]));
			detail.appendChild(E('table', { 'class': 'lc-table' }, [
				E('thead', {}, [ E('tr', {}, [
					E('th', {}, [_('服务器')]), E('th', {}, ['IP']),
					E('th', {}, [_('状态')]), E('th', {}, [_('映射')]), E('th', {}, ['RTT'])
				]) ]),
				pt
			]));
		}

		detail.appendChild(E('div', { 'class': 'lc-raw' }, [
			_('目标：') + targetText(w.target) + ' · ' +
			_('尝试 ') + fmtNum(lat.attempts) + _(' 次 / 成功 ') + fmtNum(lat.ok_count) + _(' 次 · ') +
			_('本地 STUN 端口 ') + fmtNum(nat.local_port)
		]));

		return card;
	}
});
