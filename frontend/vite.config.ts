import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
const api={target:'http://localhost:8080',changeOrigin:true};
export default defineConfig({plugins:[react()],server:{proxy:{'/process':api,'/config':api,'/metrics':api,'/openapi.yaml':api}}})
