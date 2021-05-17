#pragma once

// In C++20, we can replace find_msb with bit_width
#include <boost/multiprecision/integer.hpp>

#include <koinos/exception.hpp>
#include <koinos/log.hpp>

/**
 * Generic class for capsule exceptions.
 */
KOINOS_DECLARE_EXCEPTION( capsule_exception );

/**
 * Objects were added out of order.
 */
KOINOS_DECLARE_DERIVED_EXCEPTION( add_order_exception, capsule_exception );

/**
 * Left hash was null.  This should never happen.
 */
KOINOS_DECLARE_DERIVED_EXCEPTION( reduce_left_null_exception, capsule_exception );

/**
 * Stack underflow on edge stack when calling _reduce().  This should never happen.
 */
KOINOS_DECLARE_DERIVED_EXCEPTION( reduce_edge_underflow_exception, capsule_exception );

/**
 * Constructor was called with a null operations object.
 */
KOINOS_DECLARE_DERIVED_EXCEPTION( null_operations_exception, capsule_exception );

namespace koinos::capsule {

/**
 * tree_walker implements the core walking algorithm.
 *
 * Tree nodes are numbered using in-order traversal as follows
 * (the +/- values on edges are to help visualize the patterns in the numbering):
 *
 *                 7
 *           -4/       \+4
 *         3              11
 *     -2/   \+2      -2/    \+2
 *     1       5       9      13
 *  -1/ \+1 -1/ \+1 -1/ \+1 -1/ \+1
 *   0   2   4   6   8  10  12   14
 *
 * An operations object supplies get_hash(), empty_hash() and reduce() methods.
 *
 * Objects are added by the add_object() method.  They must be added in order.
 * When there are gaps, get_hash() is called to request the appropriate node hashes
 * to continue the walk.
 *
 * ### Creating a capsule
 *
 * - When creating a capsule, the caller should call add_object() on the leaves in order.
 * - The walker will never call get_hash() in this case, since it 
 */

template< typename HashType, typename Operations >
class tree_walker
{
   public:
      tree_walker( Operations* ops )
         : _ops(ops)
      {
         KOINOS_ASSERT( ops != nullptr, null_operations_exception, "Attempted to instantiate tree_walker with null operations object" );
      }
      virtual ~tree_walker() {}

      HashType close()
      {
         if( _last_index == -1 )
            return _ops->empty_hash();

         if( !_is_closed )
         {
            // Put down the object in its position.
            _edge.push_back( _last_obj );
            // Walk up the tree, reducing edges as we go.
            int64_t mask = 1;
            int64_t leaf_id = _last_index * 2;
            int64_t node_id = leaf_id;
            int64_t i = 0;
            while(true)
            {
               // LOG(debug) << "i=" << i;
               // LOG(debug) << "   node =" << node_id;
               // LOG(debug) << "   mask =" << mask;
               _log_edge();
               if( _last_index & mask )
               {
                  node_id -= mask;
                  if( _edge.size() == 1 )
                     break;
                  _reduce(node_id);
                  mask <<= 1;
               }
               else
               {
                  node_id += mask;
                  std::optional< HashType > h = _ops->get_hash(node_id + mask);
                  if( (!h.has_value()) && (_edge.size() == 1) )
                     break;
                  _edge.push_back(h);
                  _reduce(node_id);
                  mask <<= 1;
               }
               i++;
            }
            _is_closed = true;
         }
         if( !_edge[0] )
            return _ops->empty_hash();
         return *_edge[0];
      }

      void add_object( int64_t obj_index, HashType obj )
      {
         // LOG(debug) << "add_object(" << obj_index << ", " << obj << ")";
         KOINOS_ASSERT( obj_index > _last_index, add_order_exception, "Indexes must be presented in sorted order" );
         if( _last_index == -1 )
            _add_first_object( obj_index );
         else
            _add_later_object( obj_index, obj );
         _last_index = obj_index;
         _last_obj = obj;
      }

   private:
      void _add_first_object(int64_t obj_index)
      {
         if( obj_index > 0 )
         {
            // Walk downward, going through the paths not taken.
            int64_t leaf_id = obj_index << 1;    // Cannot overflow because of checks in add_object()
            int64_t height = boost::multiprecision::detail::find_msb(leaf_id);
            int64_t mask = 1 << height;
            int64_t node_id = mask-1;
            while( mask > 0 )
            {
               if( leaf_id & mask )
               {
                  mask >>= 1;
                  _edge.push_back( _ops->get_hash(node_id - mask) );
                  node_id += mask;
               }
               else
               {
                  mask >>= 1;
                  node_id -= mask;
               }
            }
         }
      }

      void _reduce(int64_t node_id)
      {
         KOINOS_ASSERT( _edge.size() >= 2, reduce_edge_underflow_exception, "Could not pop two edges in _reduce" );
         std::optional< HashType > b = _edge.back();
         _edge.pop_back();
         std::optional< HashType > a = _edge.back();
         KOINOS_ASSERT( a, reduce_left_null_exception, "Left hash was null in _reduce" );
         // reduce(a, null) = a, so simply don't bother to pop a in this case
         if( b )
         {
            _edge.pop_back();
            _edge.push_back( _ops->reduce( node_id, *a, *b ) );
         }
      }

      void _add_later_object(int64_t obj_index, const HashType& obj)
      {
         // Put down the object in its position.
         _edge.push_back( _last_obj );
         int64_t mask = 1;
         int64_t leaf_id = _last_index * 2;
         int64_t node_id = leaf_id;
         int64_t first_bit = boost::multiprecision::detail::find_msb(obj_index ^ _last_index);

         // Walk up the tree, reducing edges as we go.
         for( int64_t i=0; i<first_bit; i++ )
         {
            // LOG(debug) << "i=" << i;
            // LOG(debug) << "   node = " << node_id;
            // LOG(debug) << "   mask = " << mask;
            _log_edge();

            if( _last_index & mask )
            {
               node_id -= mask;
               _reduce(node_id);
               mask <<= 1;
            }
            else
            {
               node_id += mask;
               _edge.push_back( _ops->get_hash(node_id + mask) );
               _reduce(node_id);
               mask <<= 1;
            }
         }

         // We are at the pivot bit.  We need to cross to the right child,
         // then walk downward until we find the node.
         // LOG(debug) << "pivot bit";
         // LOG(debug) << "   node = " << node_id << " (left child)";
         // LOG(debug) << "   mask = " << mask;
         _log_edge();

         node_id += 2*mask;
         // LOG(debug) << "   node = " << node_id << " (right child)";

         leaf_id = obj_index * 2;
         while( mask > 0 )
         {
            // LOG(debug) << "node = " << node_id;
            // LOG(debug) << "   mask = " << mask;
            _log_edge();
            if( leaf_id & mask )
            {
               mask >>= 1;
               _edge.push_back( _ops->get_hash(node_id - mask) );
               node_id += mask;
            }
            else
            {
               mask >>= 1;
               node_id -= mask;
            }
         }
      }

      void _log_edge()
      {
         if( !_enable_edge_logging )
            return;
         std::stringstream ss;
         ss << "[";
         for( size_t i=0; i<_edge.size(); i++ )
         {
            if( i > 0 )
               ss << ", ";
            if( _edge[i] )
            {
               ss << *_edge[i];
            }
            else
            {
               ss << "nil";
            }
         }
         ss << "]";

         // LOG(debug) << "   edge =" << ss.str();
      }

      std::vector< std::optional< HashType > > _edge;
      int64_t                                  _last_index = -1;
      HashType                                 _last_obj;
      Operations*                              _ops;
      bool                                     _is_closed = false;
      bool                                     _enable_edge_logging = false;
      bool                                     _enable_debug_logging = false;
};

}
