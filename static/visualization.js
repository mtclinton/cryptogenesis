// Three.js Blockchain Visualization
import * as THREE from 'three';

let scene, camera, renderer, blockchainGroup, nodesGroup;
let blocks = new Map();
let nodes = new Map();
let animationId;

// Initialize Three.js scene
function init() {
    // Scene
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x000011);

    // Camera
    camera = new THREE.PerspectiveCamera(
        75,
        window.innerWidth / window.innerHeight,
        0.1,
        1000
    );
    camera.position.set(0, 10, 20);
    camera.lookAt(0, 0, 0);

    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    document.body.appendChild(renderer.domElement);

    // Lighting
    const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(10, 10, 5);
    scene.add(directionalLight);

    // Groups
    blockchainGroup = new THREE.Group();
    nodesGroup = new THREE.Group();
    scene.add(blockchainGroup);
    scene.add(nodesGroup);

    // Grid helper
    const gridHelper = new THREE.GridHelper(50, 50, 0x444444, 0x222222);
    scene.add(gridHelper);

    // Controls (simple orbit)
    let mouseDown = false;
    let mouseX = 0;
    let mouseY = 0;

    document.addEventListener('mousedown', (e) => {
        mouseDown = true;
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    document.addEventListener('mouseup', () => {
        mouseDown = false;
    });

    document.addEventListener('mousemove', (e) => {
        if (!mouseDown) return;
        const deltaX = e.clientX - mouseX;
        const deltaY = e.clientY - mouseY;

        const spherical = new THREE.Spherical();
        spherical.setFromVector3(camera.position);
        spherical.theta -= deltaX * 0.01;
        spherical.phi += deltaY * 0.01;
        spherical.phi = Math.max(0.1, Math.min(Math.PI - 0.1, spherical.phi));

        camera.position.setFromSpherical(spherical);
        camera.lookAt(0, 0, 0);

        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    // Zoom with wheel
    document.addEventListener('wheel', (e) => {
        const distance = camera.position.length();
        const newDistance = distance + e.deltaY * 0.1;
        if (newDistance > 5 && newDistance < 100) {
            camera.position.normalize().multiplyScalar(newDistance);
        }
    });

    // Handle window resize
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
}

// Create block visualization
function createBlock(blockData, index) {
    const geometry = new THREE.BoxGeometry(1, 1, 1);
    const material = new THREE.MeshPhongMaterial({
        color: new THREE.Color().setHex(0x00ff00 + (index % 10) * 0x001100),
        emissive: new THREE.Color().setHex(0x002200),
    });

    const block = new THREE.Mesh(geometry, material);
    block.position.set(index * 1.5, 0, 0);
    block.userData = blockData;

    // Add wireframe
    const edges = new THREE.EdgesGeometry(geometry);
    const line = new THREE.LineSegments(
        edges,
        new THREE.LineBasicMaterial({ color: 0xffffff, opacity: 0.3, transparent: true })
    );
    block.add(line);

    return block;
}

// Create connection between blocks
function createConnection(from, to) {
    const points = [
        new THREE.Vector3(from.position.x, from.position.y, from.position.z),
        new THREE.Vector3(to.position.x, to.position.y, to.position.z)
    ];
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const material = new THREE.LineBasicMaterial({ color: 0x00ffff, opacity: 0.5, transparent: true });
    return new THREE.Line(geometry, material);
}

// Create node visualization
function createNode(nodeData, index, total) {
    const geometry = new THREE.SphereGeometry(0.3, 16, 16);
    const color = nodeData.connected ? 0x00ff00 : 0xff0000;
    const material = new THREE.MeshPhongMaterial({
        color: color,
        emissive: new THREE.Color().setHex(color).multiplyScalar(0.3),
    });

    const node = new THREE.Mesh(geometry, material);

    // Position nodes in a circle
    const angle = (index / total) * Math.PI * 2;
    const radius = 15;
    node.position.set(
        Math.cos(angle) * radius,
        5,
        Math.sin(angle) * radius
    );

    node.userData = nodeData;

    return node;
}

// Store current blockchain data
let currentBlockchainData = null;

// Update blockchain visualization
function updateBlockchain(data) {
    console.log('updateBlockchain called with:', data);

    // Store data for block list
    currentBlockchainData = data;

    // Update block list
    updateBlockList(data.blocks || []);

    // Clear existing blocks
    while (blockchainGroup.children.length > 0) {
        blockchainGroup.remove(blockchainGroup.children[0]);
    }

    if (!data.blocks || data.blocks.length === 0) {
        console.log('No blocks in data, returning early');
        return;
    }

    console.log(`Creating ${data.blocks.length} blocks`);

    // Create blocks
    const blockMeshes = [];
    data.blocks.forEach((blockData, index) => {
        const blockMesh = createBlock(blockData, index);
        blockMeshes.push(blockMesh);
        blockchainGroup.add(blockMesh);

        // Create connection to previous block
        if (index > 0) {
            const connection = createConnection(blockMeshes[index - 1], blockMesh);
            blockchainGroup.add(connection);
        }
    });

    // Center the blockchain
    if (blockMeshes.length > 0) {
        const centerX = (blockMeshes.length - 1) * 1.5 / 2;
        blockchainGroup.position.x = -centerX;
    }

    // Update info
    document.getElementById('height').textContent = data.height || 0;
    document.getElementById('blockCount').textContent = data.blocks.length;
    console.log(`Updated: height=${data.height}, blocks=${data.blocks.length}`);
}

// Update block list in sidebar
function updateBlockList(blocks) {
    const blockList = document.getElementById('blockList');
    blockList.innerHTML = '';

    // Reverse blocks to show newest first
    const reversedBlocks = [...blocks].reverse();

    reversedBlocks.forEach((blockData) => {
        const blockItem = document.createElement('div');
        blockItem.className = 'block-item';
        blockItem.dataset.hash = blockData.hash;

        const height = document.createElement('div');
        height.className = 'block-height';
        height.textContent = `Block #${blockData.height}`;

        const hash = document.createElement('div');
        hash.className = 'block-hash';
        hash.textContent = blockData.hash;

        const time = document.createElement('div');
        time.className = 'block-time';
        const date = new Date(blockData.time * 1000);
        time.textContent = `Time: ${date.toLocaleString()}`;

        const txs = document.createElement('div');
        txs.className = 'block-txs';
        txs.textContent = `${blockData.transactions || 0} transaction(s)`;

        blockItem.appendChild(height);
        blockItem.appendChild(hash);
        blockItem.appendChild(time);
        blockItem.appendChild(txs);

        blockItem.addEventListener('click', () => {
            showBlockDetails(blockData);
            // Update selected state
            document.querySelectorAll('.block-item').forEach(item => {
                item.classList.remove('selected');
            });
            blockItem.classList.add('selected');
        });

        blockList.appendChild(blockItem);
    });
}

// Show block details
function showBlockDetails(blockData) {
    const detailsPanel = document.getElementById('block-details');
    const detailsContent = document.getElementById('detailsContent');

    detailsContent.innerHTML = '';

    // Block height
    const heightDiv = document.createElement('div');
    heightDiv.className = 'detail-item';
    heightDiv.innerHTML = '<label>Height</label><div class="value">' + blockData.height + '</div>';
    detailsContent.appendChild(heightDiv);

    // Block hash
    const hashDiv = document.createElement('div');
    hashDiv.className = 'detail-item';
    hashDiv.innerHTML = '<label>Hash</label><div class="value">' + blockData.hash + '</div>';
    detailsContent.appendChild(hashDiv);

    // Previous hash
    const prevHashDiv = document.createElement('div');
    prevHashDiv.className = 'detail-item';
    prevHashDiv.innerHTML = '<label>Previous Hash</label><div class="value">' + (blockData.prev_hash || 'Genesis Block') + '</div>';
    detailsContent.appendChild(prevHashDiv);

    // Time
    const timeDiv = document.createElement('div');
    timeDiv.className = 'detail-item';
    const date = new Date(blockData.time * 1000);
    timeDiv.innerHTML = '<label>Timestamp</label><div class="value">' + date.toLocaleString() + '</div>';
    detailsContent.appendChild(timeDiv);

    // Transactions count
    const txsCountDiv = document.createElement('div');
    txsCountDiv.className = 'detail-item';
    txsCountDiv.innerHTML = '<label>Transactions</label><div class="value">' + (blockData.transactions || 0) + '</div>';
    detailsContent.appendChild(txsCountDiv);

    // Transactions list
    if (blockData.transactions > 0) {
        const txsHeader = document.createElement('h4');
        txsHeader.style.color = '#f0a000';
        txsHeader.style.marginTop = '20px';
        txsHeader.textContent = 'Transactions:';
        detailsContent.appendChild(txsHeader);

        // For now, show placeholder transactions
        // In a real implementation, you'd fetch transaction details from the API
        for (let i = 0; i < blockData.transactions; i++) {
            const txItem = document.createElement('div');
            txItem.className = 'transaction-item';

            const txHash = document.createElement('div');
            txHash.className = 'tx-hash';
            txHash.textContent = `Transaction ${i + 1}${i === 0 ? ' (Coinbase)' : ''}`;

            const txInfo = document.createElement('div');
            txInfo.className = 'tx-info';
            txInfo.textContent = i === 0 ? 'Coinbase transaction (block reward)' : 'Regular transaction';

            txItem.appendChild(txHash);
            txItem.appendChild(txInfo);
            detailsContent.appendChild(txItem);
        }
    }

    detailsPanel.classList.add('visible');
}

// Close block details
document.addEventListener('DOMContentLoaded', () => {
    const closeBtn = document.getElementById('close-details');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            document.getElementById('block-details').classList.remove('visible');
            document.querySelectorAll('.block-item').forEach(item => {
                item.classList.remove('selected');
            });
        });
    }
});

// Update nodes visualization
function updateNodes(data) {
    // Clear existing nodes
    while (nodesGroup.children.length > 0) {
        nodesGroup.remove(nodesGroup.children[0]);
    }

    if (!data.nodes || data.nodes.length === 0) {
        return;
    }

    // Create nodes
    data.nodes.forEach((nodeData, index) => {
        const nodeMesh = createNode(nodeData, index, data.nodes.length);
        nodesGroup.add(nodeMesh);
    });

    // Update info
    document.getElementById('nodeCount').textContent = data.count || 0;
    console.log(`Updated nodes: count=${data.count}`);
}

// Fetch blockchain data
async function fetchBlockchain() {
    try {
        console.log('Fetching blockchain data...');
        const response = await fetch('/api/blockchain');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Received blockchain data:', data);
        updateBlockchain(data);
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
    } catch (error) {
        console.error('Error fetching blockchain:', error);
        // Show error in UI
        document.getElementById('lastUpdate').textContent = 'Error: ' + error.message;
    }
}

// Fetch nodes data
async function fetchNodes() {
    try {
        console.log('Fetching nodes data...');
        const response = await fetch('/api/nodes');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Received nodes data:', data);
        updateNodes(data);
    } catch (error) {
        console.error('Error fetching nodes:', error);
    }
}

// Animation loop
function animate() {
    animationId = requestAnimationFrame(animate);

    // Rotate blockchain group slowly
    if (blockchainGroup) {
        blockchainGroup.rotation.y += 0.005;
    }

    // Rotate nodes group
    if (nodesGroup) {
        nodesGroup.rotation.y += 0.01;
    }

    renderer.render(scene, camera);
}

// Initialize and start
init();
animate();

// Fetch data every 2 seconds
setInterval(() => {
    fetchBlockchain();
    fetchNodes();
}, 2000);

// Initial fetch
fetchBlockchain();
fetchNodes();
