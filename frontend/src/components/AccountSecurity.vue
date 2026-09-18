<script setup lang="ts">
import { onMounted, ref } from 'vue'

const props = defineProps<{
  request: <T>(path: string, method?: string, data?: unknown) => Promise<T>
}>()
const enabled = ref(false),
  loaded = ref(false),
  remaining = ref(0),
  busy = ref(false)
const error = ref(''),
  message = ref(''),
  password = ref(''),
  code = ref('')
const setup = ref<{ secret: string; qr: string } | null>(null)
const recovery = ref<string[]>([])
const saved = ref(false)
const operation = ref<'recovery' | 'disable' | null>(null)
async function run(action: () => Promise<void>) {
  busy.value = true
  error.value = ''
  message.value = ''
  try {
    await action()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Erreur inattendue'
  } finally {
    busy.value = false
  }
}
async function refresh() {
  const status = await props.request<{ enabled: boolean; recovery_remaining: number }>('/auth/mfa')
  enabled.value = status.enabled
  remaining.value = status.recovery_remaining
  loaded.value = true
}
async function begin() {
  await run(async () => {
    setup.value = await props.request('/auth/mfa/setup', 'POST', { password: password.value })
    password.value = ''
    code.value = ''
  })
}
async function enable() {
  await run(async () => {
    const result = await props.request<{ recovery_codes: string[] }>('/auth/mfa/enable', 'POST', {
      code: code.value
    })
    setup.value = null
    code.value = ''
    recovery.value = result.recovery_codes
    saved.value = false
    await refresh()
  })
}
async function cancel() {
  await run(async () => {
    await props.request('/auth/mfa/cancel', 'POST')
    setup.value = null
    password.value = ''
    code.value = ''
  })
}
async function manage() {
  await run(async () => {
    const result = await props.request<{ recovery_codes?: string[] }>(
      '/auth/mfa/' + operation.value,
      'POST',
      { password: password.value, code: code.value }
    )
    message.value = operation.value === 'disable' ? 'Le MFA est désactivé.' : ''
    operation.value = null
    password.value = ''
    code.value = ''
    recovery.value = result.recovery_codes || []
    saved.value = false
    await refresh()
  })
}
function cancelOperation() {
  operation.value = null
  password.value = ''
  code.value = ''
}
function downloadCodes() {
  const blob = new Blob(
    [
      'PhishCase — codes de récupération MFA\nChaque code est utilisable une seule fois, avec votre mot de passe.\n\n' +
        recovery.value.join('\n') +
        '\n'
    ],
    { type: 'text/plain;charset=utf-8' }
  )
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'phishcase-codes-recuperation.txt'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
onMounted(() => run(refresh))
</script>

<template>
  <section class="panel security-panel">
    <div class="panel-title">
      <h2>Authentification multifacteur</h2>
      <span v-if="loaded" class="badge" :data-state="enabled ? 'benign' : 'unreviewed'">{{
        enabled ? 'Activée' : 'Non activée'
      }}</span>
    </div>
    <p class="muted">
      Protégez votre compte avec un code généré par votre application d’authentification, en plus de
      votre mot de passe.
    </p>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <p v-if="message" role="status">{{ message }}</p>
    <p v-if="!loaded">Chargement…</p>
    <div v-else-if="recovery.length" class="recovery-box">
      <h3>Conservez vos codes de récupération</h3>
      <p>
        Le MFA est actif. Ces 10 codes ne seront affichés qu’une seule fois. Rangez-les dans votre
        gestionnaire de mots de passe : chacun remplace un code de votre application, une seule
        fois.
      </p>
      <p>Si vous quittez cette page sans les sauvegarder, vous devrez en générer de nouveaux.</p>
      <ul class="recovery-codes">
        <li v-for="item in recovery" :key="item">
          <code>{{ item }}</code>
        </li>
      </ul>
      <button class="secondary" @click="downloadCodes">Télécharger les codes</button>
      <label class="security-check"
        ><input v-model="saved" type="checkbox" /> J’ai conservé mes codes en lieu sûr.</label
      >
      <button class="primary" :disabled="!saved" @click="recovery = []">Terminer</button>
    </div>
    <form v-else-if="setup" class="security-form" @submit.prevent="enable">
      <h3>Associez votre application</h3>
      <p>
        Scannez ce QR code avec Aegis, Google Authenticator, Microsoft Authenticator, 1Password ou
        une application TOTP compatible. Cette configuration expire après 10 minutes.
      </p>
      <img
        :src="setup.qr"
        alt="QR code d’activation MFA à scanner dans votre application"
        class="mfa-qr"
        width="240"
        height="240"
      />
      <details>
        <summary>Saisir la clé manuellement</summary>
        <p class="hash">
          <code>{{ setup.secret }}</code>
        </p>
        <p class="small muted">TOTP · 6 chiffres · 30 secondes · SHA-1</p>
      </details>
      <label
        >Code de l’application<input
          v-model="code"
          inputmode="numeric"
          autocomplete="one-time-code"
          pattern="[0-9]{6}"
          maxlength="6"
          required
      /></label>
      <div class="security-actions">
        <button class="primary" :disabled="busy">Activer le MFA</button
        ><button type="button" class="secondary" :disabled="busy" @click="cancel">Annuler</button>
      </div>
    </form>
    <form v-else-if="!enabled" class="security-form" @submit.prevent="begin">
      <p>
        L’activation sera effective après vérification d’un premier code. Vos autres sessions seront
        alors déconnectées.
      </p>
      <label
        >Mot de passe actuel<input
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
          maxlength="256"
      /></label>
      <button class="primary" :disabled="busy">Configurer le MFA</button>
    </form>
    <form v-else-if="operation" class="security-form" @submit.prevent="manage">
      <h3>
        {{ operation === 'disable' ? 'Désactiver le MFA' : 'Renouveler les codes de récupération' }}
      </h3>
      <p>
        {{
          operation === 'disable'
            ? 'Votre compte sera accessible avec votre mot de passe seul.'
            : 'Tous vos anciens codes de récupération seront invalidés.'
        }}
        Vos autres sessions seront déconnectées.
      </p>
      <label
        >Mot de passe actuel<input
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
          maxlength="256"
      /></label>
      <label
        >Code de l’application ou de récupération<input
          v-model="code"
          autocomplete="one-time-code"
          required
          maxlength="64"
          spellcheck="false"
      /></label>
      <p class="small muted">
        Un code de l’application déjà utilisé est refusé : attendez le code suivant.
      </p>
      <div class="security-actions">
        <button class="primary" :disabled="busy">
          {{
            operation === 'disable' ? 'Confirmer la désactivation' : 'Générer de nouveaux codes'
          }}</button
        ><button type="button" class="secondary" :disabled="busy" @click="cancelOperation">
          Annuler
        </button>
      </div>
    </form>
    <div v-else>
      <p>
        Un code est demandé à chaque nouvelle connexion.
        <strong
          >{{ remaining }} code{{ remaining > 1 ? 's' : '' }} de récupération disponible{{
            remaining > 1 ? 's' : ''
          }}.</strong
        >
      </p>
      <p v-if="remaining < 3" class="error">Pensez à générer de nouveaux codes de récupération.</p>
      <div class="security-actions">
        <button class="secondary" @click="operation = 'recovery'">Renouveler les codes</button
        ><button class="secondary" @click="operation = 'disable'">Désactiver le MFA</button>
      </div>
    </div>
  </section>
</template>
