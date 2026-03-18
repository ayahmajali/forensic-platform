module.exports = {
  apps: [
    {
      name: 'forensic-platform',
      script: 'python',
      args: '-m uvicorn main:app --host 0.0.0.0 --port 8000',
      cwd: '/home/user/webapp/backend',
      env: {
        NODE_ENV: 'development',
        PORT: 8000,
        PYTHONPATH: '/home/user/webapp/backend'
      },
      watch: false,
      instances: 1,
      exec_mode: 'fork',
      interpreter: 'none'
    }
  ]
}
