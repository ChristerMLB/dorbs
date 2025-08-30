import * as THREE from "./three.module.min.js";
import { GLTFLoader } from "./GLTFLoader.js"

const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(
  75,
  600 / 400,
  0.1,
  1000
);

const renderer = new THREE.WebGLRenderer({ alpha: true });
renderer.setSize(600, 400);
renderer.setClearColor(0x000000, 0);
document.getElementById("threedee").appendChild(renderer.domElement);

camera.position.z = 2.5;

const light = new THREE.DirectionalLight(0xca1800, 1);
light.position.set(1, 1, 2).normalize();
scene.add(light);

const loader = new GLTFLoader();
let model;

loader.load('./suzanne.glb', (gltf) => {
  model = gltf.scene;
  model.scale.set(1, 1, 1);
  scene.add(model);
});

function animate() {
  requestAnimationFrame(animate);

  if (model) {
    model.rotation.y += 0.01; // spin around Y axis
  }

  renderer.render(scene, camera);
}
animate();