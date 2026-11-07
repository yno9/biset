// Export and import of the identity's messages and contacts as one plain JMAP file.
import { createJmapExport, decodeJmapExport, encodeJmapExport, importJmapExport } from '../../store/vault/jmap-export.ts'
import { showSysMsg } from '../ui/shell.ts'
import type { AccountVault } from './account-vault.ts'

export interface MessageArchive {
  exportMessages(): Promise<void>
  importMessages(): Promise<void>
}

function downloadFile(bytes: Uint8Array, filename: string): void {
  const url = URL.createObjectURL(new Blob([bytes.slice()]))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

function chooseFile(): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json,.biset,application/json'
    input.onchange = () => {
      const file = input.files?.[0]
      if (!file) { reject(new Error('No import file selected')); return }
      void file.arrayBuffer().then(value => resolve(new Uint8Array(value)), reject)
    }
    input.click()
  })
}

export function messageArchive(vault: AccountVault): MessageArchive {
  const { identityId, readModel, store } = vault
  return {
    async exportMessages() {
      const exported = await createJmapExport({ identityId, snapshot: await readModel.snapshot(), events: await store.readVaultEvents(identityId), download: blobId => readModel.download(blobId) })
      // Plain JSON: whoever can open this account's dashboard already sees everything the file contains.
      downloadFile(encodeJmapExport(exported), `biset-messages-${exported.exportedAt.replaceAll(':', '-')}.json`)
    },
    async importMessages() {
      const file = decodeJmapExport(await chooseFile())
      // The file is plain JSON that anyone could have written. Its own identity must be this account (importJmapExport refuses
      // otherwise), and the user confirms what it claims before anything is committed; every message it adds is marked $imported.
      if (file.identityId !== identityId) throw new Error('This export belongs to another account')
      if (!confirm(`Import ${file.emails.length} messages and ${file.contactCards?.length ?? 0} contacts exported from this account on ${new Date(file.exportedAt).toLocaleString()}? Messages it adds are marked as imported.`)) return
      const result = await importJmapExport(file, {
        identityId, actorDeviceId: vault.deviceId, snapshot: await readModel.snapshot(), events: await store.readVaultEvents(identityId),
        ...vault.authoring, commit: records => store.commitIncomingRecords(records),
      })
      if (result.events.length) {
        await vault.projector.recomputeEmails(identityId, result.events.flatMap(event => event.targetIds))
        await vault.pushToSiblings(result.events)
        await vault.refresh()
      }
      showSysMsg(`Import: ${result.added} added, ${result.skipped} skipped, ${result.excluded} excluded, ${result.missingBodies} missing bodies; contacts ${result.contactsAdded} added, ${result.contactsUpdated} updated`)
    },
  }
}
