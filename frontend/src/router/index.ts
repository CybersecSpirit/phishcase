import { createRouter, createWebHistory } from 'vue-router'
const Workspace = () => import('@/views/WorkspaceView.vue')
export const workspaceRoutes = [
  '/',
  '/dashboard',
  '/cases',
  '/cases/:id',
  '/analyses',
  '/analyses/:id',
  '/iocs',
  '/iocs/:id',
  '/campaigns',
  '/campaigns/:id',
  '/search',
  '/integrations',
  '/security',
  '/users'
].map((path) => ({ path, component: Workspace }))
export default createRouter({ history: createWebHistory(), routes: workspaceRoutes })
