// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
using System;

namespace SQLBench
{
    //Create a Node class
    class Node
    {
        public Node LeftNode;
        public Node RightNode;
        public long Data;
        public void DisplayNode()
        {
            //output for console application to display all the nodes
            Console.Write(Data + " ");
        }
    }
    class Tree
    {      
        //Crreate root node
            public Node root;
            public Tree()
            {
                root = null;
            }
            ~Tree()
            {

            }
            public Node ReturnRoot()
            {
                return root;
            }
            public void AddNode(long mydata)
            {
                //create a new node
                Node newNode = new Node();
                //assign Data in node to a long integer
                newNode.Data = mydata;
                //check root for null value 
                //if root is null assign newNode to root else 
                //assign a parent node and check left and right children
                if (root == null)
                    root = newNode;
                else
                {
                    Node current = root;
                    Node parent;
                    while (true)
                    {
                        parent = current;
                        if (mydata < current.Data)
                        {
                            current = current.LeftNode;
                            if (current == null)
                            {
                                parent.LeftNode = newNode;
                                break;
                            }
                        }
                        else
                        {
                            current = current.RightNode;
                            if (current == null)
                            {
                                parent.RightNode = newNode;
                                break;
                            }
                        }
                    }
                }

            }
            public void Preorder(Node Root)
            {
                //reorder sort for tree
                if (Root != null)
                {
                   // Console.Write(Root.Data + " ");
                    Preorder(Root.LeftNode);
                    Preorder(Root.RightNode);
                }
            }
            public void Inorder(Node Root)
            {
                //in order sort for nodes
                if (Root != null)
                {
                    Inorder(Root.LeftNode);
                    //Console.Write(Root.Data + " ");
                    Inorder(Root.RightNode);
                }
            }
            public void Postorder(Node Root)
            {
                //post order sort
                if (Root != null)
                {
                    Postorder(Root.LeftNode);
                    Postorder(Root.RightNode);
                   // Console.Write(Root.Data + " ");
                }
            }
            public Node findNode(int index, Node Root)
            {
                //find the node if the root is not null
                if (Root != null)
                {
                    if (index == Root.Data)
                        return Root;
                    if (index < Root.Data)
                        return findNode(index, Root.LeftNode);
                    else
                        return findNode(index, Root.RightNode);
                }
                return null;
            }
            public int GetTreeDepth()
            {
                //return tree depth
                return this.GetTreeDepth(this.root);
            }
            private int GetTreeDepth(Node Root)
            {
                //get tree depth
                return Root == null ? 0 : Math.Max(GetTreeDepth(Root.LeftNode), GetTreeDepth(Root.RightNode)) + 1;
            }
    }
}
