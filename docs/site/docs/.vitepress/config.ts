import { defineConfig } from 'vitepress'

export default defineConfig({
    title: 'Aethelred SDK',
    description: 'Enterprise AI Blockchain SDK — Documentation',
    base: '/docs/',

    head: [
        ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
        ['meta', { name: 'theme-color', content: '#6366f1' }],
        ['meta', { property: 'og:title', content: 'Aethelred SDK Documentation' }],
        ['meta', { property: 'og:description', content: 'Enterprise-grade AI Blockchain SDK with post-quantum cryptography' }],
    ],

    themeConfig: {
        logo: '/logo.svg',
        siteTitle: 'Aethelred SDK',

        nav: [
            { text: 'Guide', link: '/guide/getting-started' },
            {
                text: 'API Reference', items: [
                    { text: 'Go SDK', link: '/api/go/' },
                    { text: 'Rust SDK', link: '/api/rust/' },
                    { text: 'TypeScript SDK', link: '/api/typescript/' },
                    { text: 'Python SDK', link: '/api/python/' },
                ]
            },
            { text: 'Cryptography', link: '/cryptography/overview' },
            { text: 'CLI', link: '/cli/installation' },
            { text: 'Changelog', link: '/changelog' },
        ],

        sidebar: {
            '/guide/': [
                {
                    text: 'Getting Started',
                    items: [
                        { text: 'Introduction', link: '/guide/introduction' },
                        { text: 'Quick Start', link: '/guide/getting-started' },
                        { text: 'Installation', link: '/guide/installation' },
                        { text: 'Architecture', link: '/guide/architecture' },
                    ]
                },
                {
                    text: 'Core Concepts',
                    items: [
                        { text: 'Digital Seals', link: '/guide/digital-seals' },
                        { text: 'TEE Attestation', link: '/guide/tee-attestation' },
                        { text: 'zkML Proofs', link: '/guide/zkml-proofs' },
                        { text: 'Sovereign Data', link: '/guide/sovereign-data' },
                    ]
                },
                {
                    text: 'Compute',
                    items: [
                        { text: 'Runtime & Devices', link: '/guide/runtime' },
                        { text: 'Tensor Operations', link: '/guide/tensors' },
                        { text: 'Neural Networks', link: '/guide/neural-networks' },
                        { text: 'Distributed Training', link: '/guide/distributed' },
                        { text: 'Quantization', link: '/guide/quantization' },
                    ]
                },
                {
                    text: 'Blockchain',
                    items: [
                        { text: 'Connecting to Network', link: '/guide/network' },
                        { text: 'Submitting Jobs', link: '/guide/jobs' },
                        { text: 'Model Registry', link: '/guide/model-registry' },
                        { text: 'Validators', link: '/guide/validators' },
                    ]
                },
            ],
            '/api/go/': [
                {
                    text: 'Go SDK',
                    items: [
                        { text: 'Overview', link: '/api/go/' },
                        { text: 'Client', link: '/api/go/client' },
                        { text: 'Runtime', link: '/api/go/runtime' },
                        { text: 'Tensor', link: '/api/go/tensor' },
                        { text: 'Neural Network', link: '/api/go/nn' },
                        { text: 'Cryptography', link: '/api/go/crypto' },
                    ]
                },
            ],
            '/api/rust/': [
                {
                    text: 'Rust SDK',
                    items: [
                        { text: 'Overview', link: '/api/rust/' },
                        { text: 'sovereign', link: '/api/rust/sovereign' },
                        { text: 'attestation', link: '/api/rust/attestation' },
                        { text: 'crypto', link: '/api/rust/crypto' },
                        { text: 'zktensor', link: '/api/rust/zktensor' },
                        { text: 'client', link: '/api/rust/client' },
                    ]
                },
            ],
            '/api/typescript/': [
                {
                    text: 'TypeScript SDK',
                    items: [
                        { text: 'Overview', link: '/api/typescript/' },
                        { text: 'Runtime', link: '/api/typescript/runtime' },
                        { text: 'Tensor', link: '/api/typescript/tensor' },
                        { text: 'Module', link: '/api/typescript/module' },
                    ]
                },
            ],
            '/cryptography/': [
                {
                    text: 'Cryptography',
                    items: [
                        { text: 'Overview', link: '/cryptography/overview' },
                        { text: 'Security Parameters', link: '/cryptography/security-parameters' },
                        { text: 'HSM Deployment', link: '/cryptography/hsm-deployment' },
                        { text: 'Key Management', link: '/cryptography/key-management' },
                    ]
                },
            ],
            '/cli/': [
                {
                    text: 'CLI & Tools',
                    items: [
                        { text: 'Installation', link: '/cli/installation' },
                        { text: 'Configuration', link: '/cli/configuration' },
                        { text: 'Commands', link: '/cli/commands' },
                        { text: 'Shell Completions', link: '/cli/completions' },
                    ]
                },
            ],
        },

        socialLinks: [
            { icon: 'github', link: 'https://github.com/aethelred' },
        ],

        search: {
            provider: 'local',
        },

        footer: {
            message: 'Released under the Apache-2.0 License.',
            copyright: 'Copyright © 2024-present Aethelred Team',
        },

        editLink: {
            pattern: 'https://github.com/aethelred/docs/edit/main/docs/:path',
            text: 'Edit this page on GitHub',
        },
    },
})
