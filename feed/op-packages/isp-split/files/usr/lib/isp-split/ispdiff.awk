# 两个运营商集合的三段差异：仅主源 / 仅校验源 / 共同，并计算 Jaccard
#
# 用法：
#   awk -v vf=<校验源区间文件> [-v outp=<仅主源区间输出>] [-v outv=<仅校验源区间输出>] \
#       -f ispdiff.awk <主源区间文件>
#
# 输入格式：两边的区间文件都必须是「每行 <起始> <结束>，升序、互不重叠」，
#          也就是 cidr2range.awk | sort | merge.awk 的输出（零填充十位定宽）。
# 输出（stdout 一行六列）：
#           <主源地址数> <校验源地址数> <共同> <仅主> <仅校验> <Jaccard 百分比>
#
# 为什么用扫描线而不是逐条 CIDR 比对：
#   运营商集合动辄上千段，"每段对每段"是 O(n*m)；排序后双指针是 O(n+m)，
#   在 4 千行量级一次 diff 只要几十毫秒，路由器上完全无感。
#
# 注意：awk 函数里除第一个参数外多写的形参才是局部变量，这里用显式形参
#       （i/j/k/s/e 都是全局的，只用一次，不影响正确性）。

BEGIN {
	nv = 0
	while ((getline line < vf) > 0) {
		if (line == "") continue
		split(line, a, " ")
		if (a[1] == "" || a[2] == "") continue
		nv++
		vs[nv] = a[1] + 0
		ve[nv] = a[2] + 0
	}
	close(vf)
	np = 0
}

{
	if ($1 == "" || $2 == "") next
	np++
	ps[np] = $1 + 0
	pe[np] = $2 + 0
}

END {
	ptot = 0
	for (i = 1; i <= np; i++) ptot += pe[i] - ps[i] + 1
	vtot = 0
	for (i = 1; i <= nv; i++) vtot += ve[i] - vs[i] + 1

	# 交集长度（双指针）
	common = 0
	i = 1
	j = 1
	while (i <= np && j <= nv) {
		s = (ps[i] > vs[j]) ? ps[i] : vs[j]
		e = (pe[i] < ve[j]) ? pe[i] : ve[j]
		if (s <= e) common += e - s + 1
		if (pe[i] < ve[j]) i++
		else if (ve[j] < pe[i]) j++
		else { i++; j++ }
	}

	# 仅主源区间（主源减去校验源）
	if (outp != "") {
		j = 1
		for (i = 1; i <= np; i++) {
			s = ps[i]
			e = pe[i]
			while (j <= nv && ve[j] < s) j++
			k = j
			while (k <= nv && vs[k] <= e) {
				if (vs[k] > s) print s " " (vs[k] - 1) > outp
				if (ve[k] + 1 > s) s = ve[k] + 1
				if (s > e) break
				k++
			}
			if (s <= e) print s " " e > outp
		}
		close(outp)
	}

	# 仅校验源区间（校验源减去主源）
	if (outv != "") {
		i = 1
		for (j = 1; j <= nv; j++) {
			s = vs[j]
			e = ve[j]
			while (i <= np && pe[i] < s) i++
			k = i
			while (k <= np && ps[k] <= e) {
				if (ps[k] > s) print s " " (ps[k] - 1) > outv
				if (pe[k] + 1 > s) s = pe[k] + 1
				if (s > e) break
				k++
			}
			if (s <= e) print s " " e > outv
		}
		close(outv)
	}

	if (ptot + vtot - common > 0)
		jac = common * 100 / (ptot + vtot - common)
	else
		jac = 100
	printf "%.0f %.0f %.0f %.0f %.0f %.2f\n", ptot, vtot, common, ptot - common, vtot - common, jac
}
