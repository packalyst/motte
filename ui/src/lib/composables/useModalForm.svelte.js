import { toast } from '../../stores/app.js'

/**
 * Composable for managing modal forms with create/edit modes.
 *
 * Usage:
 *   const modal = useModalForm({
 *     defaults: { name: '', port: 80, enabled: true },
 *     onSubmit: async (data, mode, editId) => {
 *       if (mode === 'create') {
 *         await apiPost('/api/items', data)
 *       } else {
 *         await apiPut(`/api/items/${editId}`, data)
 *       }
 *     },
 *     onSuccess: () => reload(),
 *     successMsg: { create: 'Item created', edit: 'Item updated' }
 *   })
 *
 *   // In template:
 *   <button onclick={() => modal.openCreate()}>Add</button>
 *   <button onclick={() => modal.openEdit(item)}>Edit</button>
 *
 *   <Modal open={modal.isOpen} onClose={modal.close}>
 *     <input bind:value={modal.formData.name} />
 *     <button onclick={modal.submit} disabled={modal.loading}>Save</button>
 *   </Modal>
 *
 * @param {Object} options - Modal form options
 * @param {Object} options.defaults - Default form values
 * @param {Function} options.onSubmit - Submit handler (data, mode, editId) => Promise
 * @param {Function} options.onSuccess - Success callback
 * @param {Object} options.successMsg - Success messages { create, edit }
 * @param {string} options.errorMsg - Error message prefix
 * @param {string} options.idField - Field name for ID (default: 'id')
 * @returns {Object} Modal form state and methods
 */
export function useModalForm(options = {}) {
  const {
    defaults = {},
    onSubmit,
    onSuccess,
    successMsg = { create: 'Created successfully', edit: 'Updated successfully' },
    errorMsg = 'Operation failed',
    idField = 'id'
  } = options

  let isOpen = $state(false)
  let mode = $state('create') // 'create' | 'edit'
  let editId = $state(null)
  let loading = $state(false)
  let formData = $state({ ...defaults })

  function openCreate(initialData = {}) {
    formData = { ...defaults, ...initialData }
    editId = null
    mode = 'create'
    isOpen = true
  }

  function openEdit(item, customMapper = null) {
    if (customMapper) {
      formData = customMapper(item)
    } else {
      // Map item fields to form data, using defaults for missing fields
      const mapped = { ...defaults }
      for (const key of Object.keys(defaults)) {
        if (item[key] !== undefined) {
          mapped[key] = item[key]
        }
      }
      formData = mapped
    }
    editId = item[idField]
    mode = 'edit'
    isOpen = true
  }

  function close() {
    isOpen = false
    // Reset after animation
    setTimeout(() => {
      formData = { ...defaults }
      editId = null
      mode = 'create'
    }, 200)
  }

  async function submit() {
    if (!onSubmit) return

    loading = true
    try {
      await onSubmit(formData, mode, editId)
      const msg = mode === 'create' ? successMsg.create : successMsg.edit
      if (msg) toast(msg, 'success')
      close()
      if (onSuccess) onSuccess()
    } catch (e) {
      toast(`${errorMsg}: ${e.message}`, 'error')
    } finally {
      loading = false
    }
  }

  // Helper to update a single field
  function setField(field, value) {
    formData[field] = value
  }

  // Helper to update multiple fields
  function setFields(updates) {
    formData = { ...formData, ...updates }
  }

  return {
    get isOpen() { return isOpen },
    set isOpen(v) { isOpen = v },
    get mode() { return mode },
    get editId() { return editId },
    get loading() { return loading },
    get formData() { return formData },
    set formData(v) { formData = v },
    get isEdit() { return mode === 'edit' },
    get isCreate() { return mode === 'create' },
    openCreate,
    openEdit,
    close,
    submit,
    setField,
    setFields
  }
}

/**
 * Simpler modal state for confirmation or info modals.
 *
 * Usage:
 *   const deleteModal = useModal()
 *
 *   <button onclick={() => deleteModal.open(item)}>Delete</button>
 *
 *   <ConfirmModal
 *     open={deleteModal.isOpen}
 *     onClose={deleteModal.close}
 *     onConfirm={() => handleDelete(deleteModal.data)}
 *   />
 *
 * @returns {Object} { isOpen, data, open, close }
 */
export function useModal() {
  let isOpen = $state(false)
  let data = $state(null)

  function open(itemData = null) {
    data = itemData
    isOpen = true
  }

  function close() {
    isOpen = false
    setTimeout(() => { data = null }, 200)
  }

  return {
    get isOpen() { return isOpen },
    set isOpen(v) { isOpen = v },
    get data() { return data },
    open,
    close
  }
}

/**
 * Composable for managing inline edit state.
 *
 * Usage:
 *   const inline = useInlineEdit({
 *     onSave: async (id, value) => {
 *       await apiPut(`/api/items/${id}`, { name: value })
 *     }
 *   })
 *
 *   // In template:
 *   {#if inline.isEditing(item.id)}
 *     <input bind:value={inline.value} />
 *     <button onclick={inline.save}>Save</button>
 *     <button onclick={inline.cancel}>Cancel</button>
 *   {:else}
 *     <span ondblclick={() => inline.start(item.id, item.name)}>{item.name}</span>
 *   {/if}
 *
 * @param {Object} options
 * @param {Function} options.onSave - Save handler (id, value) => Promise
 * @param {Function} options.onSuccess - Success callback
 * @returns {Object} Inline edit state and methods
 */
export function useInlineEdit(options = {}) {
  const { onSave, onSuccess } = options

  let editingId = $state(null)
  let value = $state('')
  let loading = $state(false)

  function isEditing(id) {
    return editingId === id
  }

  function start(id, currentValue) {
    editingId = id
    value = currentValue
  }

  function cancel() {
    editingId = null
    value = ''
  }

  async function save() {
    if (!onSave || editingId === null) return

    loading = true
    try {
      await onSave(editingId, value)
      cancel()
      if (onSuccess) onSuccess()
    } catch (e) {
      toast(`Failed to save: ${e.message}`, 'error')
    } finally {
      loading = false
    }
  }

  return {
    get editingId() { return editingId },
    get value() { return value },
    set value(v) { value = v },
    get loading() { return loading },
    isEditing,
    start,
    cancel,
    save
  }
}
