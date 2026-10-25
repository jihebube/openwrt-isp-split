'use strict';
'require view';
'require fs';
'require ui';

/*
 * LuCI 配置页：运营商 → 策略映射 / 多线路 DNS / 域名分流
 *
 * 所有文件解析与改写都由 `isp-split conf` 在 shell 侧完成（带校验和回滚），
 * 这里只负责渲染表单、收集值、回传。前端不直接拼配置文件。
 */

var CMD = '/usr/sbin/isp-split';

function run(args) {
	return fs.exec(CMD, args);
}

return view.extend({
	load: function() {
		return run(['conf', 'get']);
	},

	render: function(res) {
		var self = this;
		var out = (res && res.stdout) || '';

		var mode = 'bind';
		var policies = [];
		var isp = [];
		var dns = [];
		var domains = [];

		out.split('\n').forEach(function(line) {
			if (!line)
				return;
			var f = line.split('\t');
			if (f[0] === 'dns_mode')
				mode = (f[1] || 'bind').trim();
			else if (f[0] === 'policies')
				policies = (f[1] || '').trim().split(/\s+/).filter(Boolean);
			else if (f[0] === 'isp' && f.length >= 5)
				isp.push({ src: f[1], set: f[2], policy: f[3], enabled: f[4] === '1' });
			else if (f[0] === 'dns' && f.length >= 3)
				dns.push({ policy: f[1], dns: f[2] });
			else if (f[0] === 'domain' && f.length >= 3)
				domains.push({ domain: f[1], policy: f[2] });
		});

		if (!isp.length) {
			return E('div', { 'class': 'cbi-map' }, [
				E('h2', {}, [ _('运营商分流 · 配置') ]),
				E('div', { 'class': 'cbi-map-descr' }, [
					_('读不到 /etc/isp-split.conf 的 ISP_TABLE，请先确认已安装并执行过 isp-split fetch。')
				])
			]);
		}

		/* ---------------- 运营商映射表 ---------------- */

		var ispBody = E('tbody', {});
		isp.forEach(function(row) {
			var sel = E('select', { 'class': 'cbi-input-select' }, policies.map(function(p) {
				return E('option', { 'value': p, 'selected': p === row.policy ? '' : null }, [ p ]);
			}));
			sel.addEventListener('change', function() { row.policy = sel.value; });

			var chk = E('input', { 'type': 'checkbox', 'checked': row.enabled ? '' : null });
			chk.addEventListener('change', function() { row.enabled = chk.checked; });

			ispBody.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ row.src ]),
				E('td', { 'class': 'td' }, [ E('code', {}, [ row.set ]) ]),
				E('td', { 'class': 'td' }, [ sel ]),
				E('td', { 'class': 'td' }, [ chk ])
			]));
		});

		/* ---------------- 多线路 DNS ---------------- */

		var modeSel = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': 'bind', 'selected': mode === 'bind' ? '' : null }, [ 'bind（dnsmasq @接口 绑定）' ]),
			E('option', { 'value': 'mark', 'selected': mode === 'mark' ? '' : null }, [ 'mark（nft 按目标 DNS 打标）' ])
		]);

		var dnsBody = E('tbody', {});
		var known = [ 'wan_only', 'wanb_only' ];
		policies.forEach(function(p) { if (known.indexOf(p) < 0) known.push(p); });
		known.forEach(function(p) {
			var cur = null;
			dns.forEach(function(r) { if (r.policy === p) cur = r; });
			if (!cur && p !== 'wan_only' && p !== 'wanb_only')
				return;
			if (!cur) {
				cur = { policy: p, dns: '' };
				dns.push(cur);
			}
			var inp = E('input', { 'type': 'text', 'class': 'cbi-input-text',
				'placeholder': 'DNS 地址', 'value': cur.dns });
			inp.addEventListener('input', function() { cur.dns = inp.value.trim(); });

			dnsBody.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ E('code', {}, [ p ]) ]),
				E('td', { 'class': 'td' }, [ inp ])
			]));
		});

		/* ---------------- 域名分流 ---------------- */

		var domArea = E('textarea', {
			'class': 'cbi-input-textarea',
			'rows': 6,
			'style': 'width:100%;font-family:monospace',
			'placeholder': '每行一条：域名后缀:策略　例如\nbilivideo.com:wanb_only'
		}, [ domains.map(function(d) { return d.domain + ':' + d.policy; }).join('\n') ]);

		var result = E('pre', {
			'id': 'cfg-out',
			'style': 'max-height:16em;overflow:auto;white-space:pre-wrap;font-family:monospace;' +
				'font-size:12px;padding:10px;border-radius:4px;border:1px solid rgba(128,128,128,.3)',
			'hidden': ''
		}, [ '' ]);

		function showResult(text) {
			result.textContent = text;
			result.removeAttribute('hidden');
		}

		function save(apply) {
			var ispVal = isp.map(function(r) {
				return r.src + ':' + r.set + ':' + r.policy + ':' + (r.enabled ? '1' : '0');
			}).join('|');

			var dnsVal = dns.filter(function(r) { return r.dns; })
				.map(function(r) { return r.policy + ':' + r.dns; }).join('|');

			var domVal = domArea.value.split('\n')
				.map(function(s) { return s.trim(); })
				.filter(function(s) { return s && s.indexOf('#') !== 0; })
				.join('|');

			var log = [];

			function step(args) {
				return run(args).then(function(r) {
					var t = ((r.stdout || '') + (r.stderr || '')).trim();
					log.push('$ isp-split ' + args.join(' ') + '\n' + (t || '  (无输出)'));
					return r;
				});
			}

			step(['conf', 'set', 'isp_table', ispVal])
				.then(function() { return step(['conf', 'set', 'dns_table', dnsVal]); })
				.then(function() { return step(['conf', 'set', 'domain_split', domVal]); })
				.then(function() { return step(['conf', 'set', 'dns_mode', modeSel.value]); })
				.then(function() {
					if (!apply)
						return null;
					return step(['wire'])
						.then(function() { return step(['apply']); })
						.then(function() { return step(['dns']); });
				})
				.then(function() {
					showResult(log.join('\n\n'));
					ui.addNotification(null, E('p', {}, [
						apply ? _('已保存并生效') : _('已保存。改动需执行「保存并生效」或手动 wire/apply 后才生效')
					]), 'info');
				})
				.catch(function(e) {
					showResult(log.join('\n\n') + '\n\n错误: ' + String(e));
					ui.addNotification(null, E('p', {}, [ '操作失败：' + String(e) ]), 'danger');
				});
		}

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('运营商分流 · 配置') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('运营商到策略的映射、每条线的 DNS、以及需要钉到具体线路的域名。'),
				_('改动写入 /etc/isp-split.conf，写入前会校验，语法不合法会自动回滚。')
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('运营商 → 策略') ]),
				E('table', { 'class': 'table cbi-section-table' }, [
					E('thead', {}, [ E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, [ _('运营商') ]),
						E('th', { 'class': 'th' }, [ _('集合') ]),
						E('th', { 'class': 'th' }, [ _('策略') ]),
						E('th', { 'class': 'th' }, [ _('启用') ])
					]) ]),
					ispBody
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('多线路 DNS') ]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, [ _('出线方式') ]),
					E('div', { 'class': 'cbi-value-field' }, [
						modeSel,
						E('div', { 'class': 'cbi-value-description' }, [
							_('bind 依赖 dnsmasq 的 @接口；mark 用 nft 按目标 DNS 打标，OpenClash 接管 DNS 时更稳。')
						])
					])
				]),
				E('table', { 'class': 'table cbi-section-table' }, [
					E('thead', {}, [ E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, [ _('策略') ]),
						E('th', { 'class': 'th' }, [ _('该线路使用的 DNS') ])
					]) ]),
					dnsBody
				])
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('域名分流') ]),
				E('div', { 'class': 'cbi-value-description' }, [
					_('这些后缀的域名会强制用对应线路的 DNS 解析，让 CDN 返回本运营商节点。留空则不启用。')
				]),
				domArea
			]),

			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'cbi-button cbi-button-neutral',
					'click': function() { save(false); }
				}, [ _('仅保存') ]),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-positive',
					'click': function() { save(true); }
				}, [ _('保存并生效') ])
			]),

			result
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
