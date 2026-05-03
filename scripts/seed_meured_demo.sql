BEGIN;

-- Categories (idempotent)
INSERT INTO meured_content."MeuredCategory" (id, slug, name, "createdAt", "updatedAt")
VALUES
  ('11111111-1111-1111-1111-111111111111', 'casos-clinicos', 'Casos Clínicos', now(), now()),
  ('22222222-2222-2222-2222-222222222222', 'investigacion', 'Investigación & Evidencia', now(), now()),
  ('33333333-3333-3333-3333-333333333333', 'formacion', 'Preguntas & Aprendizaje', now(), now()),
  ('44444444-4444-4444-4444-444444444444', 'farmacologia', 'Farmacología Clínica', now(), now()),
  ('55555555-5555-5555-5555-555555555555', 'sistema-salud', 'Sistema de Salud', now(), now()),
  ('66666666-6666-6666-6666-666666666666', 'tecnologia', 'IA & Tecnología', now(), now()),
  ('77777777-7777-7777-7777-777777777777', 'bienestar', 'Bienestar del Médico', now(), now())
ON CONFLICT (slug) DO UPDATE
SET name = EXCLUDED.name, "updatedAt" = now();

-- Posts (idempotent by id)
INSERT INTO meured_content."MeuredPost" (
  id,
  "authorAuthUserId",
  "categoryId",
  title,
  body,
  status,
  "createdAt",
  "updatedAt"
)
VALUES
  (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1',
    'demo-u1',
    '77777777-7777-7777-7777-777777777777',
    'Burnout en residencia: señales tempranas y qué hacer',
    'Abro este hilo para compartir recursos y estrategias que me ayudaron a identificar burnout a tiempo: higiene del sueño, límites, terapia y apoyo entre colegas. ¿Qué les ha funcionado a ustedes?',
    'PUBLISHED',
    now() - interval '1 day',
    now() - interval '1 day'
  ),
  (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2',
    'demo-u2',
    '11111111-1111-1111-1111-111111111111',
    'Caso clínico: fiebre prolongada + citopenias (discusión)',
    'Paciente con 3 semanas de fiebre, pérdida de peso, esplenomegalia y pancitopenia. ¿Qué priorizan: infeccioso, hematológico o autoinmune? Compartan su enfoque paso a paso.',
    'PUBLISHED',
    now() - interval '6 hours',
    now() - interval '6 hours'
  ),
  (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3',
    'demo-u3',
    '22222222-2222-2222-2222-222222222222',
    'Resumen rápido: evidencia reciente en GLP-1 y riesgo CV',
    'Compilo un resumen de puntos clave (diseño del estudio, outcomes, limitaciones y aplicabilidad en nuestro contexto). Si alguien tiene enlaces a guías locales, los agregamos.',
    'PUBLISHED',
    now() - interval '10 hours',
    now() - interval '10 hours'
  ),
  (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4',
    'demo-u1',
    '33333333-3333-3333-3333-333333333333',
    'Tips de estudio: ¿cómo armar un plan de 8 semanas para exámenes?',
    'Estoy armando un plan de 8 semanas. ¿Qué método usan para repasar (Anki, bancos de preguntas, casos)? Dejo una plantilla y la mejoramos entre todos.',
    'PUBLISHED',
    now() - interval '2 hours',
    now() - interval '2 hours'
  ),
  (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5',
    'demo-u2',
    '66666666-6666-6666-6666-666666666666',
    'IA en consulta: checklist práctico para no improvisar',
    'Comparto una checklist para usar IA de forma segura: anonimización, verificación, evitar sesgos, y documentar fuentes. ¿Qué herramientas usan y qué riesgos han visto?',
    'PUBLISHED',
    now() - interval '12 hours',
    now() - interval '12 hours'
  )
ON CONFLICT (id) DO UPDATE
SET
  "authorAuthUserId" = EXCLUDED."authorAuthUserId",
  "categoryId" = EXCLUDED."categoryId",
  title = EXCLUDED.title,
  body = EXCLUDED.body,
  status = EXCLUDED.status,
  "updatedAt" = now();

COMMIT;
