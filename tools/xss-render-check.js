#!/usr/bin/env node
/*
 * XSS 回归渲染断言（AUDIT-SECURITY-v2 §A-15）
 *
 * 目标：不是“再写一个渲染器”，而是把真实的
 * luci-app-isp-split/.../linecheck.js 放进一个最小的 DOM/E() 桩里，用伪造的
 * last.json（每个字符串字段都是 payload）跑一遍 card()/paint()，然后断言：
 *   1) 所有 payload 只以文本节点出现；
 *   2) 全文唯一的 innerHTML 写入来自 svgIcon()，内容是静态 SVG 图标；
 *   3) payload 没有进入任何 innerHTML 字符串。
 *
 * LuCI 的 E() 对字符串子项调用 document.createTextNode()，本桩用
 * { text: ... } 表示文本节点，效果等价。没有 node 的环境由
 * tools/selftest.sh 退化为静态 grep（innerHTML 不得与外网字段拼接）。
 *
 * 用法：node tools/xss-render-check.js [linecheck.js 路径]
 * 退出码：0 通过；1 失败（打印原因）。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const file = process.argv[2] || path.join(
	__dirname, '..', 'luci-app-isp-split', 'htdocs',
	'luci-static', 'resources', 'view', 'isp-split', 'linecheck.js');
const source = fs.readFileSync(file, 'utf8');

const PAYLOADS = [
	'<img src=x onerror=alert(1)>',
	'"><svg onload=alert(2)>',
	'</span><iframe srcdoc="<script>alert(3)</script>">',
	'<script>alert(4)</script>',
	'A"B\\C\nD'
];

let innerHTMLWrites = [];

function makeEl(tag) {
	const el = {
		tag: tag,
		attrs: {},
		children: [],
		textContent: '',
		className: '',
		style: {},
		appendChild: function (c) {
			this.children.push(c);
			this.lastChild = c;
			return c;
		},
		removeChild: function (c) {
			const i = this.children.indexOf(c);
			if (i >= 0) this.children.splice(i, 1);
			return c;
		},
		setAttribute: function (k, v) {
			this.attrs[k] = (typeof v === 'function') ? v : String(v);
		},
		removeAttribute: function (k) { delete this.attrs[k]; },
		getAttribute: function (k) { return this.attrs[k]; },
		hasAttribute: function (k) {
			return Object.prototype.hasOwnProperty.call(this.attrs, k);
		},
		classList: { add: function () {}, remove: function () {} },
		querySelector: function () { return null; },
		lastChild: null
	};
	Object.defineProperty(el, 'firstChild', {
		get: function () { return this.children.length ? this.children[0] : null; }
	});
	Object.defineProperty(el, 'innerHTML', {
		get: function () { return this._html || ''; },
		set: function (v) {
			this._html = String(v);
			innerHTMLWrites.push(this._html);
		}
	});
	return el;
}

function E(tag, attrs, children) {
	const el = makeEl(tag);
	if (attrs && typeof attrs === 'object' && !Array.isArray(attrs)) {
		Object.keys(attrs).forEach(function (k) {
			if (typeof attrs[k] === 'function')
				el.attrs[k] = attrs[k];
			else
				el.setAttribute(k, attrs[k]);
		});
	}
	(Array.isArray(children) ? children : (children === undefined ? [] : [children]))
		.forEach(function (c) {
			if (c === null || c === undefined)
				return;
			if (Array.isArray(c)) {
				c.forEach(function (x) { if (x !== null && x !== undefined) el.appendChild(E.text(x)); });
			} else if (typeof c === 'string' || typeof c === 'number') {
				el.appendChild({ text: String(c) });
			} else {
				el.appendChild(c);
			}
		});
	return el;
}
E.text = function (s) { return { text: String(s) }; };

const sandbox = {
	E: E,
	_: function (s) { return s; },
	L: { resource: function (p) { return p; }, resolveDefault: function (p) { return p; } },
	document: {
		createElement: makeEl,
		body: { contains: function () { return true; } }
	},
	view: { extend: function (o) { return o; } },
	fs: { read: function () { return Promise.resolve(''); }, stat: function () { return Promise.resolve(null); }, exec: function () { return Promise.resolve({}); } },
	ui: { addNotification: function () {} },
	baseclass: { extend: function (o) { return o; } },
	window: {},
	setInterval: function () { return 0; },
	clearInterval: function () {},
	Date: Date,
	JSON: JSON,
	Math: Math,
	String: String,
	Array: Array,
	Number: Number,
	Object: Object,
	console: console
};
vm.createContext(sandbox);

// linecheck.js 顶层是 `return view.extend({...})`；用函数包一层才能 return。
const view = vm.runInContext('(function () {\n' + source + '\n})()', sandbox, { filename: file });
if (!view || typeof view.card !== 'function' || typeof view.paint !== 'function')
	throw new Error('linecheck.js 没有导出 card()/paint()，XSS 断言无法执行');

function payload(i) { return PAYLOADS[i % PAYLOADS.length]; }

function forgedWan(i) {
	const p = payload(i);
	return {
		iface: p,
		device: p,
		up: true,
		state: p,
		wan_ip: p,
		ip_class: p,
		exit_ip: p,
		exit_ok: true,
		exit_probe: [{ url: p, http_code: 200, err: p, ms: 1, ok: true }],
		multi_nat: true,
		isp: p,
		isp_label: p,
		target: { domain: p, ip: p, isp: p, label: p, mode: 'same_isp' },
		latency: {
			dns_ms: p, dns_scope: p, dns_server: p,
			tcp_ms: p, tls_ms: p, ttfb_ms: p, total_ms: p,
			jitter_ms: p, loss_pct: p, attempts: p, ok_count: p, samples: [p]
		},
		http: { code: 200, ok: true },
		geo: { status: 'ok', provider: p, location: p, ip: p },
		nat: {
			type: p, label: p, confidence: p, detail: p, socat: true, local_port: 1234,
			probes: [{ server: p, ip: p, status: 'ok', mapped: p, rtt_ms: 12 }]
		},
		score: {
			total: 50, grade: 'C',
			breakdown: [
				{ key: 'nat', label: p, value: p, points: 1, max: 30, reason: p },
				{ key: 'latency', label: p, value: p, points: 1, max: 30, reason: p },
				{ key: 'stability', label: p, value: p, points: 1, max: 25, reason: p },
				{ key: 'availability', label: p, value: p, points: 1, max: 15, reason: p }
			],
			caps: [p], advice: p
		}
	};
}

const data = {
	version: payload(0),
	generated: Math.floor(Date.now() / 1000),
	interval: 60,
	geo_enabled: true,
	geo_provider: payload(1),
	socat: true,
	errors: [payload(2)],
	wans: [forgedWan(0), forgedWan(1), forgedWan(2), forgedWan(3), forgedWan(4)]
};

const inst = Object.assign({}, view, {
	data: data,
	cardsBox: makeEl('div'),
	metaBox: makeEl('div'),
	msgBox: makeEl('div'),
	baseGen: 0,
	busy: false
});
inst.paint();

function walk(node, texts, attrs) {
	if (!node || typeof node !== 'object')
		return;
	if (typeof node.text === 'string')
		texts.push(node.text);
	if (node.attrs) {
		Object.keys(node.attrs).forEach(function (k) {
			if (typeof node.attrs[k] === 'string')
				attrs.push(node.attrs[k]);
		});
	}
	if (Array.isArray(node.children))
		node.children.forEach(function (c) { walk(c, texts, attrs); });
}

const texts = [];
const attrs = [];
walk(inst.cardsBox, texts, attrs);
texts.push(String(inst.metaBox.textContent || ''));

const joined = texts.join('\n');
const missing = PAYLOADS.filter(function (p) { return joined.indexOf(p) < 0; });
if (missing.length)
	throw new Error('payload 没有以文本节点出现（渲染层把外部字段丢了？）: ' + JSON.stringify(missing));

const badHTML = innerHTMLWrites.filter(function (h) {
	return !/^<svg viewBox="0 0 24 24"/.test(h) ||
		PAYLOADS.some(function (p) { return h.indexOf(p) >= 0; });
});
if (badHTML.length)
	throw new Error('innerHTML 出现非静态图标内容: ' + JSON.stringify(badHTML.slice(0, 2)));

if (!innerHTMLWrites.length)
	throw new Error('没有观察到 svgIcon 的 innerHTML 写入，断言失效（视图实现变了？）');

console.log('XSS render check OK: ' + PAYLOADS.length + ' payloads as text nodes, ' +
	innerHTMLWrites.length + ' innerHTML writes all static SVG');