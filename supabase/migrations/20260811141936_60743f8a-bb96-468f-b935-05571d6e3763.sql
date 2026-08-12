CREATE TABLE public.analyses (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  file_name TEXT NOT NULL,
  file_size BIGINT NOT NULL,
  sha256 TEXT NOT NULL,
  package_name TEXT,
  version_name TEXT,
  version_code BIGINT,
  min_sdk INTEGER,
  target_sdk INTEGER,
  rules_version TEXT NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  overall_score INTEGER NOT NULL DEFAULT 0,
  score_security INTEGER NOT NULL DEFAULT 0,
  score_privacy INTEGER NOT NULL DEFAULT 0,
  score_quality INTEGER NOT NULL DEFAULT 0,
  score_coverage INTEGER NOT NULL DEFAULT 0,
  findings_high INTEGER NOT NULL DEFAULT 0,
  findings_medium INTEGER NOT NULL DEFAULT 0,
  findings_low INTEGER NOT NULL DEFAULT 0,
  findings_info INTEGER NOT NULL DEFAULT 0,
  result JSONB NOT NULL,
  ai_summary TEXT
);

CREATE INDEX analyses_created_at_idx ON public.analyses (created_at DESC);
CREATE INDEX analyses_package_idx ON public.analyses (package_name);

GRANT SELECT, INSERT ON public.analyses TO anon;
GRANT SELECT, INSERT, UPDATE ON public.analyses TO authenticated;
GRANT ALL ON public.analyses TO service_role;

ALTER TABLE public.analyses ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Analyses are publicly readable" ON public.analyses FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "Anyone can create an analysis" ON public.analyses FOR INSERT TO anon, authenticated WITH CHECK (true);

CREATE TABLE public.comparisons (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  base_analysis_id UUID NOT NULL REFERENCES public.analyses(id) ON DELETE CASCADE,
  head_analysis_id UUID NOT NULL REFERENCES public.analyses(id) ON DELETE CASCADE,
  rules_version TEXT NOT NULL,
  diff JSONB NOT NULL
);

CREATE INDEX comparisons_created_at_idx ON public.comparisons (created_at DESC);

GRANT SELECT, INSERT ON public.comparisons TO anon;
GRANT SELECT, INSERT ON public.comparisons TO authenticated;
GRANT ALL ON public.comparisons TO service_role;

ALTER TABLE public.comparisons ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Comparisons are publicly readable" ON public.comparisons FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "Anyone can create a comparison" ON public.comparisons FOR INSERT TO anon, authenticated WITH CHECK (true);