#include <koinos/chain/types.hpp>
#include <koinos/chain/apply_context.hpp>

namespace koinos::chain {

void apply_context::console_append( const std::string& val )
{
   _pending_console_output += val;
}

std::string apply_context::get_pending_console_output()
{
   std::string buf = _pending_console_output;
   _pending_console_output.clear();
   return buf;
}

void apply_context::set_state_node( state_node_ptr node )
{
   _current_state_node = node;
}

state_node_ptr apply_context::get_state_node()const
{
   return _current_state_node;
}

void apply_context::clear_state_node()
{
   _current_state_node.reset();
}

const variable_blob& apply_context::get_contract_call_args() const
{
   KOINOS_ASSERT( _stack.size(), koinos::exception, "" );
   return _stack[ _stack.size() - 1 ].call_args;
}

variable_blob apply_context::get_contract_return() const
{
   KOINOS_ASSERT( _stack.size(), koinos::exception, "" );
   return _stack[ _stack.size() - 1 ].call_return;
}

void apply_context::set_contract_return( const variable_blob& ret )
{
   KOINOS_ASSERT( _stack.size(), koinos::exception, "" );
   _stack[ _stack.size() - 1 ].call_return = ret;
}

void apply_context::set_key_authority( const crypto::public_key& key )
{
   _key_auth = key;
}

void apply_context::clear_authority()
{
   _key_auth.reset();
}

const account_type& apply_context::get_caller()const
{
   KOINOS_ASSERT( _stack.size() > 1 , koinos::exception, "" );
   return _stack[ _stack.size() - 2 ].call;
}

void apply_context::push_frame( stack_frame&& frame )
{
   _stack.emplace_back( std::move(frame) );
}

stack_frame apply_context::pop_frame()
{
   KOINOS_ASSERT( _stack.size() , koinos::exception, "" );
   auto frame = _stack[ _stack.size() - 1 ];
   _stack.pop_back();
   return frame;
}

} // koinos::chain
