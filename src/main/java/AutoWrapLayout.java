import java.awt.*;

class AutoWrapLayout implements LayoutManager2 {
    private final int hgap, vgap;
    private final int top, left, bottom, right;

    AutoWrapLayout(int hgap, int vgap) {
        this(hgap, vgap, 4, 4, 4, 4); // 默认很小的内边距
    }
    AutoWrapLayout(int hgap, int vgap, int top, int left, int bottom, int right) {
        this.hgap = Math.max(0, hgap);
        this.vgap = Math.max(0, vgap);
        this.top = top; this.left = left; this.bottom = bottom; this.right = right;
    }

    @Override public Dimension preferredLayoutSize(Container parent) { return computeSize(parent, SizeType.PREF); }
    @Override public Dimension minimumLayoutSize(Container parent)   { return computeSize(parent, SizeType.MIN); }
    @Override public Dimension maximumLayoutSize(Container target)  { return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE); }
    @Override public void layoutContainer(Container parent) {
        Insets ins = parent.getInsets();
        int maxW = parent.getWidth() - ins.left - ins.right - left - right;
        if (maxW <= 0) return;

        int x = left, y = top;
        int rowH = 0;

        for (Component c : parent.getComponents()) {
            if (!c.isVisible()) continue;
            Dimension d = c.getPreferredSize();
            if (x > left && x + d.width > maxW + left) { // 换行
                x = left;
                y += rowH + vgap;
                rowH = 0;
            }
            c.setBounds(ins.left + x, ins.top + y, d.width, d.height);
            x += d.width + hgap;
            rowH = Math.max(rowH, d.height);
        }
        // 末行高度不用额外加 vgap；容器高度由上层滚动面板/父容器决定
    }

    private enum SizeType { PREF, MIN }
    private Dimension computeSize(Container parent, SizeType type) {
        Insets ins = parent.getInsets();
        int maxW = 0;
        // 首选宽度：尽量给一行（用于在没有实际宽度时的估计）
        int lineW = left, rowH = 0, prefW = 0, prefH = top;

        for (Component c : parent.getComponents()) {
            if (!c.isVisible()) continue;
            Dimension d = (type == SizeType.MIN) ? c.getMinimumSize() : c.getPreferredSize();
            // 估算时假定“无限宽度一行”
            if (lineW > left) lineW += hgap;
            lineW += d.width;
            rowH = Math.max(rowH, d.height);
            maxW = Math.max(maxW, lineW);
        }
        if (rowH > 0) prefH += rowH; // 只有一行时的高度（不加多余 vgap）
        prefW = maxW + right;

        // 再把容器自身的边距算上
        prefW += ins.left + ins.right;
        prefH += bottom + ins.top + ins.bottom;

        // 不让高度为 0
        if (prefH == 0) prefH = top + bottom + ins.top + ins.bottom + 1;
        return new Dimension(prefW, prefH);
    }

    @Override public void addLayoutComponent(String name, Component comp) {}
    @Override public void removeLayoutComponent(Component comp) {}
    @Override public void addLayoutComponent(Component comp, Object constraints) {}
    @Override public float getLayoutAlignmentX(Container target) { return 0f; }
    @Override public float getLayoutAlignmentY(Container target) { return 0f; }
    @Override public void invalidateLayout(Container target) {}
}
