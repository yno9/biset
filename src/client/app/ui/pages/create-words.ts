// The word on the Create button, in the languages it turns through. Several sets; CREATE_PRESET says which one is used.
export const CREATE_WORDS = {
  world: ['Create', '作成', 'Créer', 'Crear', 'Erstellen', 'Criar'],
  asia: ['Create', '作成', '创建', '만들기', 'สร้าง', 'Tạo'],
  europe: ['Create', 'Créer', 'Crear', 'Erstellen', 'Creare', 'Criar', 'Skapa', 'Maak'],
} as const

export const CREATE_PRESET: keyof typeof CREATE_WORDS = 'world'
/** How long a word stays before the next one comes in. */
export const CREATE_WORD_MS = 4000
