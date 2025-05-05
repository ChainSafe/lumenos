package core

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

type Leaf interface {
	WriteTo(w io.Writer) (n int64, err error)
}

type MerkleTree struct {
	Root         *Node
	merkleRoot   []byte
	Leafs        []*Node
	hashStrategy func() hash.Hash
}

type Node struct {
	Tree   *MerkleTree
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	Hash   []byte
	C      Leaf
}

type MerklePath [][]byte

func (n *Node) isLeaf() bool {
	return n.leaf
}

func calculateNodeHash(node *Node) ([]byte, error) {
	if node.Tree == nil || node.Tree.hashStrategy == nil {
		return nil, errors.New("node is not associated with a tree or tree has no hash strategy")
	}
	h := node.Tree.hashStrategy()

	if node.isLeaf() {
		if node.C == nil {
			return nil, errors.New("leaf node has no content (Leaf)")
		}
		var buf bytes.Buffer
		if _, err := node.C.WriteTo(&buf); err != nil {
			return nil, fmt.Errorf("failed to write leaf content to buffer: %w", err)
		}
		if _, err := h.Write(buf.Bytes()); err != nil {
			return nil, fmt.Errorf("failed to write leaf bytes to hash: %w", err)
		}
		return h.Sum(nil), nil
	}

	if node.Left == nil || node.Right == nil {
		return nil, errors.New("internal node is missing children")
	}
	if node.Left.Hash == nil || node.Right.Hash == nil {
		return nil, errors.New("internal node children missing hashes")
	}

	combined := make([]byte, 0, len(node.Left.Hash)+len(node.Right.Hash))
	combined = append(combined, node.Left.Hash...)
	combined = append(combined, node.Right.Hash...)

	if _, err := h.Write(combined); err != nil {
		return nil, fmt.Errorf("failed to write combined child hashes to hash: %w", err)
	}
	return h.Sum(nil), nil
}

func NewTree(leafs []Leaf) (*MerkleTree, error) {
	hashStrat := sha256.New
	return NewTreeWithHashStrategy(leafs, hashStrat)
}

func NewTreeWithHashStrategy(leafs []Leaf, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	if hashStrategy == nil {
		return nil, errors.New("hash strategy cannot be nil")
	}

	tree := &MerkleTree{
		hashStrategy: hashStrategy,
		Leafs:        make([]*Node, 0, len(leafs)),
	}

	if len(leafs) == 0 {
		tree.merkleRoot = nil
		return tree, nil
	}

	for _, l := range leafs {
		if l == nil {
			return nil, errors.New("leaf input cannot be nil")
		}
		node := &Node{
			Tree: tree,
			leaf: true,
			C:    l,
		}
		var err error
		node.Hash, err = calculateNodeHash(node)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate hash for leaf: %w", err)
		}
		tree.Leafs = append(tree.Leafs, node)
	}

	if len(tree.Leafs) == 1 {
		tree.Root = tree.Leafs[0]
		tree.merkleRoot = tree.Leafs[0].Hash
		return tree, nil
	}

	currentLevelNodes := tree.Leafs
	for len(currentLevelNodes) > 1 {
		var nextLevelNodes []*Node

		for i := 0; i < len(currentLevelNodes); i += 2 {
			left := currentLevelNodes[i]
			var right *Node

			if i+1 < len(currentLevelNodes) {
				right = currentLevelNodes[i+1]
			} else {
				right = left
			}

			parent := &Node{
				Tree:  tree,
				leaf:  false,
				Left:  left,
				Right: right,
			}

			var err error
			parent.Hash, err = calculateNodeHash(parent)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate hash for internal node: %w", err)
			}

			left.Parent = parent
			if i+1 < len(currentLevelNodes) {
				right.Parent = parent
			}

			nextLevelNodes = append(nextLevelNodes, parent)
		}
		currentLevelNodes = nextLevelNodes
	}

	if len(currentLevelNodes) != 1 {
		return nil, errors.New("tree construction finished with != 1 node at the root level")
	}
	tree.Root = currentLevelNodes[0]
	tree.merkleRoot = tree.Root.Hash

	return tree, nil
}

func (m *MerkleTree) MerkleRoot() []byte {
	if m == nil || m.merkleRoot == nil {
		return nil
	}
	rootCopy := make([]byte, len(m.merkleRoot))
	copy(rootCopy, m.merkleRoot)
	return rootCopy
}

func (m *MerkleTree) GetMerklePath(index uint) (MerklePath, error) {
	if m == nil || m.Root == nil {
		return nil, errors.New("cannot get path from an empty or nil tree")
	}
	numLeaves := uint(len(m.Leafs))
	if index >= numLeaves {
		return nil, fmt.Errorf("index %d out of bounds for %d leaves", index, numLeaves)
	}

	leafNode := m.Leafs[index]
	if leafNode == nil {
		// This should ideally not happen if index is in bounds and Leafs is populated correctly
		return nil, fmt.Errorf("internal error: leaf node at index %d is nil", index)
	}

	var path MerklePath
	currentNode := leafNode

	for currentNode.Parent != nil {
		parent := currentNode.Parent
		var siblingHash []byte

		if parent.Left == currentNode {
			if parent.Right != nil {
				siblingHash = parent.Right.Hash
			} else {
				return nil, errors.New("internal inconsistency: parent node missing right child unexpectedly")
			}
		} else if parent.Right == currentNode {
			if parent.Left != nil {
				siblingHash = parent.Left.Hash
			} else {
				return nil, errors.New("internal inconsistency: parent node missing left child unexpectedly")
			}
		} else {
			return nil, errors.New("internal inconsistency: node is not a child of its parent")
		}

		if siblingHash == nil {
			return nil, errors.New("internal inconsistency: sibling node hash is nil")
		}

		path = append(path, siblingHash)
		currentNode = parent
	}

	return path, nil
}

// VerifyMerklePath checks if a given leaf, its Merkle path, and the leaf's original index
// correctly hash up to the provided root hash.
func VerifyMerklePath(leaf Leaf, path MerklePath, root []byte, index uint) (bool, error) {
	if leaf == nil {
		return false, errors.New("leaf cannot be nil")
	}
	if root == nil {
		return false, errors.New("root hash cannot be nil")
	}
	h := sha256.New()

	// Calculate the initial hash of the leaf
	var buf bytes.Buffer
	if _, err := leaf.WriteTo(&buf); err != nil {
		return false, fmt.Errorf("failed to write leaf to buffer for verification: %w", err)
	}
	if _, err := h.Write(buf.Bytes()); err != nil {
		return false, fmt.Errorf("failed to write leaf bytes to hash for verification: %w", err)
	}
	currentHash := h.Sum(nil)
	h.Reset()

	currentIndex := index
	for _, siblingHash := range path {
		if siblingHash == nil {
			return false, errors.New("path contains a nil hash")
		}

		var combined []byte
		if currentIndex%2 == 0 {
			combined = append(currentHash, siblingHash...)
		} else {
			combined = append(siblingHash, currentHash...)
		}

		if _, err := h.Write(combined); err != nil {
			return false, fmt.Errorf("failed to write combined hash during verification: %w", err)
		}
		currentHash = h.Sum(nil)
		h.Reset()

		currentIndex /= 2
	}

	return bytes.Equal(currentHash, root), nil
}
