namespace Helper
{
    /// <summary>
    /// Xdows Model 判毒阈值预设。宽松 / 严格 在各引擎模式的默认固定阈值上偏移，
    /// 中等 即引擎默认值（推荐阈值仍由模型旁的 *.threshold.json 提供）。
    /// </summary>
    public static class ModelThresholdPresets
    {
        public const string Loose = "Loose";
        public const string Medium = "Medium";
        public const string Strict = "Strict";
        public const string Custom = "Custom";

        // 引擎默认固定判毒阈值（Standard / Flash / Pro），与 TrainingConfig 及原生 g_fixedThresholds 一致。
        public const float DefaultStandard = 92f;
        public const float DefaultFlash = 96f;
        public const float DefaultPro = 94f;

        public const float LooseOffset = -5f;
        public const float StrictOffset = 3f;

        /// <summary>未设置自定义阈值时的初值。</summary>
        public const float DefaultCustom = 92f;

        public static (float Standard, float Flash, float Pro) Resolve(string? preset, double customValue)
        {
            if (preset == Custom)
            {
                float value = (float)customValue;
                return (value, value, value);
            }

            float offset = preset switch
            {
                Loose => LooseOffset,
                Strict => StrictOffset,
                _ => 0f
            };

            return (DefaultStandard + offset, DefaultFlash + offset, DefaultPro + offset);
        }
    }
}
