// A display name for an identity that has not chosen one: two English words, an adjective and a bird, animal or plant ("Quiet Heron",
// "Amber Fern"), worked out from the identity's SCID. Every device of the identity gets the same name with nothing to agree on, an alias
// change leaves it alone, and the first pick of a new identity is already a name (so a colour and an initial can come from it).
const ADJECTIVES = [
  'Amber', 'Ancient', 'Bold', 'Bright', 'Brisk', 'Calm', 'Clever', 'Cosmic', 'Crisp', 'Curious', 'Dapper', 'Eager',
  'Electric', 'Fancy', 'Fearless', 'Gentle', 'Golden', 'Happy', 'Hidden', 'Humble', 'Jolly', 'Keen', 'Kind', 'Lively',
  'Lucky', 'Mellow', 'Merry', 'Mighty', 'Misty', 'Modest', 'Nimble', 'Noble', 'Odd', 'Patient', 'Peppy', 'Plucky',
  'Proud', 'Quick', 'Quiet', 'Rapid', 'Rosy', 'Rustic', 'Shy', 'Silent', 'Silver', 'Sleepy', 'Snowy', 'Spry',
  'Steady', 'Stormy', 'Sunny', 'Swift', 'Tidy', 'Tiny', 'Vivid', 'Warm', 'Wild', 'Wise', 'Witty', 'Zesty',
  'Cheery', 'Dusty', 'Frosty', 'Glossy',
] as const
const NOUNS = [
  // birds
  'Heron', 'Sparrow', 'Finch', 'Wren', 'Robin', 'Swallow', 'Owl', 'Falcon', 'Crane', 'Kingfisher', 'Puffin', 'Pelican',
  'Plover', 'Starling', 'Magpie', 'Lark', 'Ibis', 'Egret', 'Osprey', 'Kestrel', 'Thrush', 'Tern', 'Swan', 'Dove',
  'Jay', 'Kiwi', 'Parrot', 'Toucan', 'Quail', 'Raven', 'Pigeon', 'Albatross',
  // animals
  'Otter', 'Badger', 'Fox', 'Lynx', 'Hare', 'Deer', 'Beaver', 'Panda', 'Koala', 'Lemur', 'Marten', 'Weasel',
  'Hedgehog', 'Squirrel', 'Seal', 'Dolphin', 'Whale', 'Walrus', 'Llama', 'Alpaca', 'Gecko', 'Newt', 'Tortoise', 'Turtle',
  'Bison', 'Moose', 'Ferret', 'Mole', 'Mouse', 'Lizard', 'Yak', 'Zebra',
  // plants
  'Fern', 'Maple', 'Willow', 'Birch', 'Cedar', 'Aspen', 'Clover', 'Daisy', 'Iris', 'Lotus', 'Moss', 'Orchid',
  'Poppy', 'Sage', 'Thistle', 'Violet', 'Bamboo', 'Basil', 'Hazel', 'Juniper', 'Lavender', 'Mint', 'Oak', 'Pine',
  'Reed', 'Rowan', 'Tulip', 'Yarrow', 'Acorn', 'Bramble', 'Lily', 'Ivy',
] as const

/** FNV-1a over the text, 32 bits: stable, and spread well enough for picking out of a list. */
function hash(text: string, seed: number): number {
  let h = (0x811c9dc5 ^ seed) >>> 0
  for (let index = 0; index < text.length; index += 1) { h ^= text.charCodeAt(index); h = Math.imul(h, 0x01000193) >>> 0 }
  return h
}

export function defaultDisplayName(scid: string): string {
  return `${ADJECTIVES[hash(scid, 1) % ADJECTIVES.length]} ${NOUNS[hash(scid, 2) % NOUNS.length]}`
}
