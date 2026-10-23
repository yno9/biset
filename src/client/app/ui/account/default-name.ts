// A display name for an identity that has not chosen one: two English words picked at random, an adjective and a bird, animal or
// plant ("Quiet Heron", "Amber Fern"). It is made once and kept on the identity's own card, which the devices share through the Vault,
// so what a name is does not depend on the device that made it.
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


const pick = <T>(list: readonly T[]): T => list[crypto.getRandomValues(new Uint32Array(1))[0]! % list.length]!

export function randomDisplayName(): string {
  return `${pick(ADJECTIVES)} ${pick(NOUNS)}`
}
